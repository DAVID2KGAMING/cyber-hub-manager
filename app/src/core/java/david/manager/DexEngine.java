package david.manager;
import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.zip.*;import org.json.*;
import org.jf.dexlib2.*;import org.jf.dexlib2.iface.*;import org.jf.dexlib2.dexbacked.*;import org.jf.dexlib2.immutable.*;import org.jf.dexlib2.writer.pool.DexPool;
import org.jf.baksmali.*;import org.jf.baksmali.Adaptors.ClassDefinition;import org.jf.baksmali.formatter.BaksmaliWriter;import org.jf.smali.*;
import jadx.api.*;import jadx.plugins.input.dex.DexInputPlugin;

public final class DexEngine {
 final File root;File source,session;final Map<String,File>files=new LinkedHashMap<>();final Map<String,DexBackedDexFile>dexes=new LinkedHashMap<>();final SortedMap<String,ClassDef>classes=new TreeMap<>();final Map<String,String>owners=new HashMap<>();String sourceHash;JadxDecompiler jadx;String jadxMode="";
 public DexEngine(File r){root=r;root.mkdirs();}
 public JSONObject open(File src,JSONArray names)throws Exception{close();files.clear();dexes.clear();classes.clear();owners.clear();source=src;sourceHash=FileOps.sha256(src);session=new File(root,UUID.randomUUID().toString());session.mkdirs();
  if(names.length()==0)throw new IOException("Select at least one DEX");
  for(int n=0;n<names.length();n++){String name=names.getString(n);File out=FileOps.child(session,new File(name).getName());byte[] data=src.getName().endsWith(".dex")?FileOps.read(src,256L*1024*1024):FileOps.zipEntry(src,name,256L*1024*1024);FileOps.writeAtomic(out,data,false);files.put(name,out);DexBackedDexFile d=DexFileFactory.loadDexFile(out,Opcodes.getDefault());dexes.put(name,d);for(ClassDef c:d.getClasses()){if(classes.containsKey(c.getType()))throw new IOException("Duplicate class across selected DEX files: "+c.getType());classes.put(c.getType(),c);owners.put(c.getType(),name);}}
  return new JSONObject().put("count",classes.size()).put("files",new JSONArray(files.keySet())).put("source",src.getPath());
 }
 public JSONArray tree(String prefix)throws Exception{
  TreeMap<String,JSONObject>items=new TreeMap<>();String p=prefix.replace('.','/');
  for(String type:classes.tailMap("L"+p).keySet()){
   String name=type.substring(1,type.length()-1);if(!name.startsWith(p))break;
   String remain=name.substring(p.length());int slash=remain.indexOf('/');
   if(slash>=0){String folder=remain.substring(0,slash);if(!items.containsKey("0"+folder)){
    String compact=compactPackage(p+folder+"/");
    items.put("0"+folder,new JSONObject().put("name",compact.substring(p.length(),compact.length()-1).replace('/','.')).put("prefix",compact).put("dir",true));
   }}else items.put("1"+remain,new JSONObject().put("name",remain).put("class",type).put("dex",owners.get(type)).put("dir",false));
  }return new JSONArray(items.values());
 }
 private String compactPackage(String prefix){
  // Collapse only single-child package chains; never skip a package with classes.
  for(;;){String only=null;boolean stop=false;
   for(String type:classes.tailMap("L"+prefix).keySet()){
    if(!type.startsWith("L"+prefix))break;
    String rest=type.substring(prefix.length()+1,type.length()-1);int slash=rest.indexOf('/');
    if(slash<0){stop=true;break;}String child=rest.substring(0,slash);
    if(only!=null&&!only.equals(child)){stop=true;break;}only=child;
   }
   if(stop||only==null)return prefix;prefix+=only+"/";
  }
 }
 String smali(ClassDef c)throws IOException{StringWriter writer=new StringWriter();BaksmaliOptions o=new BaksmaliOptions();o.apiLevel=28;new ClassDefinition(o,c).writeTo(new BaksmaliWriter(writer));return writer.toString();}
 public JSONObject code(String type,String mode,String decompiler)throws Exception{ClassDef c=classes.get(type);if(c==null)throw new IOException("Class not found");String text;
  if(mode.equals("java")){
   if(jadx==null||!jadxMode.equals(decompiler)){close();JadxArgs a=new JadxArgs();a.setInputFiles(new ArrayList<>(files.values()));a.setSkipResources(true);a.setThreadsCount(2);a.setInlineAnonymousClasses(false);a.setInlineMethods(false);a.setUseSourceNameAsClassAlias(false);a.setDeobfuscationOn(false);a.setRenameFlags(EnumSet.noneOf(JadxArgs.RenameEnum.class));a.setDecompilationMode(decompiler.equals("simple")?DecompilationMode.SIMPLE:decompiler.equals("fallback")?DecompilationMode.FALLBACK:DecompilationMode.AUTO);jadx=new JadxDecompiler(a);jadx.registerPlugin(new DexInputPlugin());jadx.load();jadxMode=decompiler;}
   JavaClass jc=jadx.searchJavaClassByOrigFullName(type.substring(1,type.length()-1).replace('/','.'));if(jc==null)jc=jadx.searchJavaClassOrItsParentByOrigFullName(type.substring(1,type.length()-1).replace('/','.'));if(jc==null)jc=jadx.searchJavaClassByOrigFullName(type.substring(1,type.length()-1).replace('/','.').replace('$','.'));
   if(jc==null){String parent=type.substring(1,type.length()-1);while(jc==null&&parent.lastIndexOf('$')>=0){parent=parent.substring(0,parent.lastIndexOf('$'));if(classes.containsKey("L"+parent+";"))jc=jadx.searchJavaClassByOrigFullName(parent.replace('/','.'));}}
   if(jc==null)throw new IOException("JADX could not locate this class");jc=jc.getTopParentClass();type="L"+jc.getRawName().replace('.','/')+";";text=jc.getCode();
  }else text="# "+owners.get(type)+"\n"+smali(c);
  return new JSONObject().put("text",text).put("class",type).put("mode",mode).put("name",type.substring(type.lastIndexOf('/')+1,type.length()-1)+(mode.equals("java")?".java":".smali")).put("dex",owners.get(type));
 }
 public JSONObject saveJava(String type,String text,File platform)throws Exception {
  if(!classes.containsKey(type))throw new IOException("Class not found");
  if(text.contains("Method not decompiled:")||text.contains("JADX ERROR:"))throw new IOException("This Java output contains an undecompiled method. Restore its Java body or edit Smali before compiling; the existing DEX has not been changed.");
  long started=System.nanoTime();Collection<? extends ClassDef> replacements=JavaEditCompiler.compile(type,text,classes,platform,session);
  applyClasses(type,replacements);return new JSONObject().put("saved",true).put("classes",replacements.size()).put("compileMs",(System.nanoTime()-started)/1000000).put("message","Java compiled into DEX. Save the project, then sign the APK.");
 }
 private void applyClasses(String rootType,Collection<? extends ClassDef> replacements)throws Exception {
  String rootOwner=owners.get(rootType);if(rootOwner==null)throw new IOException("Class not found");
  Map<String,ClassDef>updates=new HashMap<>();Set<String>affected=new LinkedHashSet<>();
  for(ClassDef c:replacements){String t=c.getType();if(!t.equals(rootType)&&!t.startsWith(rootType.substring(0,rootType.length()-1)+"$"))throw new IOException("Compiled class is outside the edited class family: "+t);updates.put(t,c);affected.add(owners.getOrDefault(t,rootOwner));}
  if(!updates.containsKey(rootType))throw new IOException("The original class is missing from compiler output");
  File transaction=new File(session,"merge-"+UUID.randomUUID());transaction.mkdirs();Map<String,File>staged=new LinkedHashMap<>(),backups=new LinkedHashMap<>();List<String>published=new ArrayList<>();
  try{
   for(String owner:affected){List<ClassDef>all=new ArrayList<>();for(Map.Entry<String,ClassDef>e:classes.entrySet())if(owner.equals(owners.get(e.getKey())))all.add(updates.getOrDefault(e.getKey(),e.getValue()));
    for(ClassDef c:updates.values())if(!owners.containsKey(c.getType())&&owner.equals(rootOwner))all.add(c);
    File changed=new File(transaction,owner+".new");DexPool.writeTo(changed.getPath(),new ImmutableDexFile(dexes.get(owner).getOpcodes(),all));DexFileFactory.loadDexFile(changed,Opcodes.getDefault());staged.put(owner,changed);
    File backup=new File(transaction,owner+".bak");FileOps.copyTree(files.get(owner),backup);backups.put(owner,backup);
   }
   try{for(String owner:affected){FileOps.replace(staged.get(owner),files.get(owner));published.add(owner);}}
   catch(Exception failure){for(String owner:published)FileOps.replace(backups.get(owner),files.get(owner));throw failure;}
   for(String owner:affected){DexBackedDexFile d=DexFileFactory.loadDexFile(files.get(owner),Opcodes.getDefault());dexes.put(owner,d);for(ClassDef c:d.getClasses()){classes.put(c.getType(),c);owners.put(c.getType(),owner);}}
   close();
  }finally{FileOps.deleteTree(transaction);}
 }
 public JSONObject save(String type,String text)throws Exception{
  if(!classes.containsKey(type))throw new IOException("Class not found");File input=new File(session,"edit.smali"),compiled=new File(session,"one.dex");FileOps.writeAtomic(input,text.getBytes(StandardCharsets.UTF_8),false);SmaliOptions o=new SmaliOptions();o.apiLevel=28;o.jobs=1;o.outputDexFile=compiled.getPath();o.verboseErrors=true;
  ByteArrayOutputStream errors=new ByteArrayOutputStream();PrintStream previous=System.err;boolean valid;
  try{System.setErr(new PrintStream(errors));valid=Smali.assemble(o,input.getPath());}finally{System.setErr(previous);}
  if(!valid)throw new IOException("Smali syntax error:\n"+errors.toString("UTF-8"));DexBackedDexFile changed=DexFileFactory.loadDexFile(compiled,Opcodes.getDefault());if(changed.getClasses().size()!=1)throw new IOException("Expected one class");ClassDef replacement=changed.getClasses().iterator().next();if(!replacement.getType().equals(type))throw new IOException("Keep the class descriptor unchanged");String owner=owners.get(type);List<ClassDef>all=new ArrayList<>();for(Map.Entry<String,ClassDef>e:classes.entrySet())if(owner.equals(owners.get(e.getKey())))all.add(e.getKey().equals(type)?replacement:e.getValue());File dest=files.get(owner),temp=new File(session,"rebuilt.dex");DexPool.writeTo(temp.getPath(),new ImmutableDexFile(dexes.get(owner).getOpcodes(),all));FileOps.replace(temp,dest);DexBackedDexFile reloaded=DexFileFactory.loadDexFile(dest,Opcodes.getDefault());dexes.put(owner,reloaded);for(ClassDef cl:reloaded.getClasses())classes.put(cl.getType(),cl);close();return new JSONObject().put("saved",true).put("message","Class assembled. Export DEX/APK to keep changes.");
 }
 public JSONObject export(File folder)throws Exception{if(!folder.isDirectory())throw new IOException("Choose an existing output folder");File output=new File(folder,DataEngine.strip(source.getName())+"-dex-edited"+(source.getName().endsWith(".dex")?".dex":".apk"));if(output.exists())throw new IOException("Output already exists; rename or remove it first");if(source.getName().endsWith(".dex"))FileOps.writeAtomic(output,FileOps.read(files.values().iterator().next(),256L*1024*1024),false);else{Map<String,byte[]>edits=new HashMap<>();for(Map.Entry<String,File>e:files.entrySet())edits.put(e.getKey(),FileOps.read(e.getValue(),256L*1024*1024));FileOps.rewriteZip(source,output,edits);}return new JSONObject().put("path",output.getPath()).put("needsSigning",!source.getName().endsWith(".dex"));}
 public JSONObject query(JSONObject a)throws Exception{return DexQueries.query(classes,a);}
 public JSONObject commit()throws Exception{
  return commit(null);
 }
 public JSONObject commit(InputStream signingKey)throws Exception{
  if(source==null||!source.isFile())throw new IOException("Source file is missing");
  if(!FileOps.sha256(source).equals(sourceHash))throw new IOException("Source changed outside this project. Export a copy instead.");
  File temp=File.createTempFile(".dex-commit-", ".tmp",source.getAbsoluteFile().getParentFile());
  File signed=new File(temp.getPath()+".signed.apk");
  try{
   if(source.getName().endsWith(".dex"))FileOps.writeAtomic(temp,FileOps.read(files.values().iterator().next(),256L*1024*1024),false);
   else{Map<String,byte[]>edits=new HashMap<>();for(Map.Entry<String,File>e:files.entrySet())edits.put(e.getKey(),FileOps.read(e.getValue(),256L*1024*1024));FileOps.rewriteZip(source,temp,edits);}
   if(signingKey!=null){if(source.getName().endsWith(".dex"))throw new IOException("DEX files are not installable APKs");ApkSigning.sign(temp,signed,signingKey);}
   if(!FileOps.sha256(source).equals(sourceHash))throw new IOException("Source changed while saving. Export a copy instead.");
   File backup=FileOps.commitWithBackup(signingKey==null?temp:signed,source);sourceHash=FileOps.sha256(source);
   return new JSONObject().put("path",source.getPath()).put("backup",backup.getPath()).put("verified",signingKey!=null).put("needsSigning",signingKey==null&&!source.getName().endsWith(".dex"));
  }finally{temp.delete();signed.delete();}
 }
 public JSONArray strings(String query)throws Exception{JSONArray out=new JSONArray();String q=query.toLowerCase(Locale.ROOT);Set<String>seen=new HashSet<>();for(DexBackedDexFile d:dexes.values())for(String s:d.getStringSection())if(s.toLowerCase(Locale.ROOT).contains(q)&&seen.add(s)){out.put(s);if(out.length()>=2000)return out;}return out;}
 public JSONArray search(String query)throws Exception{JSONArray out=new JSONArray();if(query.isEmpty())return out;String q=query.toLowerCase(Locale.ROOT);for(Map.Entry<String,ClassDef>e:classes.entrySet()){ClassDef c=e.getValue();boolean found=e.getKey().toLowerCase(Locale.ROOT).contains(q);if(!found)for(Method m:c.getMethods())if(m.getName().toLowerCase(Locale.ROOT).contains(q)){found=true;break;}if(!found)for(Field f:c.getFields())if(f.getName().toLowerCase(Locale.ROOT).contains(q)){found=true;break;}if(found){out.put(new JSONObject().put("name",e.getKey().substring(1,e.getKey().length()-1).replace('/','.')).put("class",e.getKey()));if(out.length()>=1000)break;}}return out;}
 public void close(){if(jadx!=null){jadx.close();jadx=null;}jadxMode="";}
}
