package david.manager;

import org.json.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

/** APK editing tools: manifest/package, clone, permissions, entries, hex, project folders, ARSC strings, signing key. */
public final class ApkTools {
 private ApkTools(){}
 /** What the tools need from the app; lets the JVM tests run them without Android. */
 interface Host{File workspace();void sign(File src,File dst)throws Exception;void record(String text);File androidApiJar()throws Exception;byte[] devSigningCert()throws Exception;}
 static final long MAX_ENTRY=256L*1024*1024,MAX_HEX=128L*1024*1024;
 static final String[] CLASS_ATTRS={"android:name","android:targetActivity","android:backupAgent","android:manageSpaceActivity","android:parentActivityName"};

 // ---------------------------------------------------------------- dispatch
 static Object call(Host e,JSONObject a)throws Exception{
  String op=a.getString("op");
  switch(op){
   case "manifestInfo":return manifestInfo(new File(a.getString("path")));
   case "manifestApply":return manifestApply(e,a,false);
   case "clone":return manifestApply(e,a,true);
   case "replaceEntry":return replaceEntry(e,a);
   case "deleteEntries":return deleteEntries(e,a);
   case "hexRead":return hexRead(e,a);
   case "hexFind":return hexFind(e,a);
   case "hexPatch":return hexPatch(e,a);
   case "projectDecode":return projectDecode(a);
   case "projectBuild":return projectBuild(e,a);
   case "arscStrings":return arscStrings(a);
   case "arscReplace":return arscReplace(e,a);
   case "ksStatus":return ksStatus();
   case "ksImport":return ksImport(e,a);
   case "ksGenerate":return ksGenerate(e,a);
   case "ksExport":return ksExport(e,a);
   case "ksReset":return ksReset(e);
   case "protectDetect":return ApkProtect.detect(new File(a.getString("path")));
   case "protectInfo":return ApkProtect.info(new File(a.getString("path")));
   case "protect":return ApkProtect.run(e,a);
   default:throw new IOException("Unknown APK tool: "+op);
  }
 }

 // ---------------------------------------------------------------- helpers
 static byte[] manifestBytes(File apk)throws IOException{return FileOps.zipEntry(apk,"AndroidManifest.xml",32L*1024*1024);}
 static String find(String xml,String regex,int group){Matcher m=Pattern.compile(regex).matcher(xml);return m.find()?m.group(group):"";}
 static String strip(String n){int p=n.lastIndexOf('.');return p>0?n.substring(0,p):n;}
 static File outDir(Host e,File src){File p=src.getAbsoluteFile().getParentFile();return p!=null&&p.canWrite()?p:e.workspace();}
 static File unique(File dir,String base,String ext)throws IOException{
  for(int n=0;n<1000;n++){File f=new File(dir,base+(n==0?"":"-"+(n+1))+ext);if(!f.exists())return f;}
  throw new IOException("Too many output files with this name");
 }
 static String validPackage(String p)throws IOException{
  if(p==null||!p.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))throw new IOException("Package name must look like david.manager (at least two parts, letters/digits/underscore)");
  return p;
 }
 /** Write an edited archive; APKs are signed and verified, other archives are kept as written. */
 static JSONObject publish(Host e,File src,Map<String,byte[]> repl,Set<String> removals,String suffix,boolean wantSign)throws Exception{
  File dir=outDir(e,src);boolean apk=src.getName().toLowerCase(Locale.ROOT).endsWith(".apk");
  File tmp=File.createTempFile(".apktool-",".tmp",dir);
  try{
   FileOps.rewriteZip(src,tmp,repl,removals);
   File out=unique(dir,strip(src.getName())+suffix,apk?".apk":src.getName().substring(Math.max(0,src.getName().lastIndexOf('.'))));
   boolean signed=false;
   if(apk&&wantSign){e.sign(tmp,out);signed=true;}else FileOps.replace(tmp,out);
   e.record("Wrote "+out.getName());
   return new JSONObject().put("path",out.getPath()).put("signed",signed).put("needsSigning",apk&&!signed);
  }finally{tmp.delete();}
 }
 static String replaceTag(String xml,String tags,TagEdit edit){
  Matcher m=Pattern.compile("<("+tags+")\\b[^>]*>").matcher(xml);StringBuffer sb=new StringBuffer();
  while(m.find())m.appendReplacement(sb,Matcher.quoteReplacement(edit.apply(m.group())));
  m.appendTail(sb);return sb.toString();
 }
 interface TagEdit{String apply(String tag);}
 static String setAttr(String tag,String attr,String value){
  Matcher m=Pattern.compile("(\\b"+Pattern.quote(attr)+"=\")[^\"]*(\")").matcher(tag);
  if(!m.find())return tag;return m.replaceFirst(Matcher.quoteReplacement(m.group(1)+escape(value)+m.group(2)));
 }
 static String attr(String tag,String attr){return find(tag,"\\b"+Pattern.quote(attr)+"=\"([^\"]*)\"",1);}
 static String escape(String s){return s.replace("&","&amp;").replace("<","&lt;").replace("\"","&quot;");}

 // ---------------------------------------------------------------- manifest
 static JSONObject manifestInfo(File apk)throws Exception{
  String xml=new Axml().decode(manifestBytes(apk));
  JSONArray perms=new JSONArray();Matcher m=Pattern.compile("<uses-permission(?:-sdk-23)?\\b[^>]*>").matcher(xml);
  while(m.find()){String n=attr(m.group(),"android:name");if(!n.isEmpty())perms.put(n);}
  Matcher root=Pattern.compile("<manifest\\b[^>]*>").matcher(xml);String tag=root.find()?root.group():"";
  Matcher app=Pattern.compile("<application\\b[^>]*>").matcher(xml);String atag=app.find()?app.group():"";
  return new JSONObject().put("package",attr(tag,"package")).put("versionName",attr(tag,"android:versionName")).put("versionCode",attr(tag,"android:versionCode")).put("label",attr(atag,"android:label")).put("permissions",perms);
 }
 /** Pure text edit of a decoded manifest; used by manifestApply/clone and by the tests. */
 static String editManifest(String xml,JSONObject p,boolean clone)throws Exception{
  Matcher rm=Pattern.compile("<manifest\\b[^>]*>").matcher(xml);
  if(!rm.find())throw new IOException("AndroidManifest.xml has no <manifest> element");
  String rootTag=rm.group(),oldPkg=attr(rootTag,"package");
  String newPkg=p.optString("package","").trim();
  if(!newPkg.isEmpty())validPackage(newPkg);
  boolean rename=!newPkg.isEmpty()&&!newPkg.equals(oldPkg);
  if(rename){
   final String op=oldPkg,np=newPkg;
   // 1. Relative class names must keep pointing at the ORIGINAL package.
   xml=replaceTag(xml,"application|activity|activity-alias|service|receiver|provider",tag->{
    for(String at:CLASS_ATTRS){String v=attr(tag,at);if(v.isEmpty())continue;
     String full=v.startsWith(".")?op+v:(v.indexOf('.')<0?op+"."+v:v);
     if(!full.equals(v))tag=setAttr(tag,at,full);}
    return tag;});
   // 2. Provider authorities and custom permissions move with the package (prevents install conflicts).
   xml=replaceTag(xml,"provider",tag->{String v=attr(tag,"android:authorities");return v.contains(op)?setAttr(tag,"android:authorities",v.replace(op,np)):tag;});
   xml=replaceTag(xml,"uses-permission|permission|permission-tree|permission-group",tag->{String v=attr(tag,"android:name");return v.startsWith(op+".")?setAttr(tag,"android:name",np+v.substring(op.length())):tag;});
   xml=replaceTag(xml,"application|activity|activity-alias|service|receiver|provider",tag->{String v=attr(tag,"android:permission");return v.startsWith(op+".")?setAttr(tag,"android:permission",np+v.substring(op.length())):tag;});
   // 3. The package itself.
   xml=replaceTag(xml,"manifest",tag->setAttr(tag,"package",np));
   if(clone)xml=xml.replaceAll("\\s*android:sharedUserId=\"[^\"]*\"","");
  }
  final String vn=p.optString("versionName",""),vc=p.optString("versionCode","").trim(),label=p.optString("label","");
  if(!vc.isEmpty()&&!vc.matches("[0-9]{1,10}"))throw new IOException("Version code must be a whole number");
  if(!vn.isEmpty()||!vc.isEmpty())xml=replaceTag(xml,"manifest",tag->{if(!vn.isEmpty())tag=setAttr(tag,"android:versionName",vn);if(!vc.isEmpty())tag=setAttr(tag,"android:versionCode",vc);return tag;});
  if(!label.isEmpty()){
   Matcher am=Pattern.compile("<application\\b[^>]*>").matcher(xml);
   if(am.find()){String tag=am.group();String nt=tag.contains("android:label=\"")?setAttr(tag,"android:label",label):tag.replaceFirst("<application","<application android:label=\""+Matcher.quoteReplacement(escape(label))+"\"");xml=xml.substring(0,am.start())+nt+xml.substring(am.end());}
  }
  JSONArray rem=p.optJSONArray("removePermissions");
  if(p.optBoolean("removeAllPermissions")||(rem!=null&&rem.length()>0)){
   Set<String> names=new HashSet<>();if(rem!=null)for(int i=0;i<rem.length();i++)names.add(rem.getString(i));
   final boolean all=p.optBoolean("removeAllPermissions");
   Matcher m=Pattern.compile("[ \\t]*<(uses-permission(?:-sdk-23)?)\\b([^>]*)>(?:\\s*</\\1>)?[ \\t]*\\n?").matcher(xml);StringBuffer sb=new StringBuffer();
   while(m.find()){String n=attr("<x "+m.group(2)+">","android:name");boolean drop=all?true:names.contains(n);m.appendReplacement(sb,drop?"":Matcher.quoteReplacement(m.group()));}
   m.appendTail(sb);xml=sb.toString();
  }
  return xml;
 }
 static JSONObject manifestApply(Host e,JSONObject a,boolean clone)throws Exception{
  File src=new File(a.getString("path"));if(!src.getName().toLowerCase(Locale.ROOT).endsWith(".apk"))throw new IOException("Choose an APK file");
  if(clone&&a.optString("package","").trim().isEmpty())throw new IOException("Enter the new package name");
  Axml ax=new Axml();String xml=ax.decode(manifestBytes(src));
  String edited=editManifest(xml,a,clone);
  if(edited.equals(xml))throw new IOException("Nothing to change");
  Map<String,byte[]> repl=new HashMap<>();repl.put("AndroidManifest.xml",ax.encode(edited));
  JSONObject r=publish(e,src,repl,Collections.<String>emptySet(),clone?"-clone":"-edited",a.optBoolean("sign",true));
  r.put("manifest",manifestInfo(new File(r.getString("path"))));return r;
 }

 // ---------------------------------------------------------------- entries
 static JSONObject replaceEntry(Host e,JSONObject a)throws Exception{
  File src=new File(a.getString("archive")),with=new File(a.getString("source"));String entry=a.getString("entry");
  if(!with.isFile())throw new IOException("Replacement file not found");if(with.length()>MAX_ENTRY)throw new IOException("Replacement file is too large");
  byte[] data=FileOps.read(with,MAX_ENTRY);
  String low=entry.toLowerCase(Locale.ROOT);
  if(low.endsWith(".png")&&!(data.length>8&&(data[0]&255)==0x89&&data[1]=='P'&&data[2]=='N'&&data[3]=='G'))throw new IOException("The replacement is not a PNG image");
  if((low.endsWith(".jpg")||low.endsWith(".jpeg"))&&!(data.length>3&&(data[0]&255)==0xFF&&(data[1]&255)==0xD8))throw new IOException("The replacement is not a JPEG image");
  if(low.endsWith(".webp")&&!(data.length>12&&data[0]=='R'&&data[1]=='I'&&data[2]=='F'&&data[3]=='F'&&data[8]=='W'&&data[9]=='E'))throw new IOException("The replacement is not a WebP image");
  if(low.endsWith(".xml")&&!a.optBoolean("rawXml")&&Axml.isBinary(FileOps.zipEntry(src,entry,MAX_ENTRY))&&!Axml.isBinary(data))throw new IOException("This entry is binary XML. Edit it in the text editor, or pass a compiled binary XML file");
  boolean exists;try(ZipFile z=new ZipFile(src)){exists=z.getEntry(entry)!=null;}
  if(!exists&&!a.optBoolean("add"))throw new IOException("Entry does not exist: "+entry);
  Map<String,byte[]> repl=new HashMap<>();repl.put(entry,data);
  return publish(e,src,repl,Collections.<String>emptySet(),"-edited",a.optBoolean("sign",true));
 }
 static JSONObject deleteEntries(Host e,JSONObject a)throws Exception{
  File src=new File(a.getString("archive"));JSONArray arr=a.getJSONArray("entries");Set<String> rem=new HashSet<>();
  for(int i=0;i<arr.length();i++){String n=arr.getString(i);if(n.equals("AndroidManifest.xml"))throw new IOException("AndroidManifest.xml cannot be removed");rem.add(n);}
  if(rem.isEmpty())throw new IOException("Nothing selected");
  return publish(e,src,new HashMap<String,byte[]>(),rem,"-edited",a.optBoolean("sign",true));
 }

 // ---------------------------------------------------------------- hex
 static byte[] entryOrFile(JSONObject a)throws Exception{
  String archive=a.optString("archive");
  if(!archive.isEmpty())return FileOps.zipEntry(new File(archive),a.getString("entry"),MAX_HEX);
  File f=new File(a.getString("path"));if(!f.isFile())throw new IOException("File not found");if(f.length()>MAX_HEX)throw new IOException("File is larger than 128 MB");
  return FileOps.read(f,MAX_HEX);
 }
 static JSONObject hexRead(Host e,JSONObject a)throws Exception{
  String archive=a.optString("archive");long off=a.optLong("offset",0);int len=Math.min(4096,Math.max(16,a.optInt("length",512)));
  byte[] part;long total;
  if(archive.isEmpty()){
   File f=new File(a.getString("path"));if(!f.isFile())throw new IOException("File not found");total=f.length();
   if(off<0||off>Math.max(0,total-1))off=0;off-=off%16;int n=(int)Math.min(len,total-off);part=new byte[Math.max(0,n)];
   try(RandomAccessFile r=new RandomAccessFile(f,"r")){r.seek(off);r.readFully(part);}
  }else{
   byte[] all=entryOrFile(a);total=all.length;if(off<0||off>Math.max(0,total-1))off=0;off-=off%16;int n=(int)Math.min(len,total-off);part=Arrays.copyOfRange(all,(int)off,(int)off+Math.max(0,n));
  }
  JSONArray rows=new JSONArray();
  for(int i=0;i<part.length;i+=16){
   StringBuilder hx=new StringBuilder(),as=new StringBuilder();
   for(int j=0;j<16;j++){if(i+j<part.length){int v=part[i+j]&255;hx.append(String.format("%02X",v));as.append(v>=32&&v<127?(char)v:'.');}else hx.append("  ");if(j<15)hx.append(' ');}
   rows.put(new JSONObject().put("offset",off+i).put("hex",hx.toString()).put("ascii",as.toString()));
  }
  return new JSONObject().put("total",total).put("offset",off).put("rows",rows);
 }
 static byte[] parseHex(String hex)throws IOException{
  String h=hex.replaceAll("[\\s,]|0x","");if(h.isEmpty()||h.length()%2!=0||!h.matches("[0-9A-Fa-f]+"))throw new IOException("Hex bytes must be pairs like 1F 8B 08");
  byte[] b=new byte[h.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(h.substring(i*2,i*2+2),16);return b;
 }
 static JSONObject hexFind(Host e,JSONObject a)throws Exception{
  byte[] all=entryOrFile(a);byte[] pat=a.optBoolean("text")?a.getString("pattern").getBytes(StandardCharsets.UTF_8):parseHex(a.getString("pattern"));
  if(pat.length==0)throw new IOException("Enter what to find");JSONArray hits=new JSONArray();int from=(int)Math.max(0,a.optLong("from",0));
  outer:for(int i=from;i<=all.length-pat.length&&hits.length()<200;i++){for(int j=0;j<pat.length;j++)if(all[i+j]!=pat[j])continue outer;hits.put(i);}
  return new JSONObject().put("hits",hits).put("total",all.length);
 }
 static byte[] applyPatches(byte[] data,JSONArray patches)throws Exception{
  byte[] out=data.clone();
  for(int i=0;i<patches.length();i++){JSONObject p=patches.getJSONObject(i);long off=p.getLong("offset");byte[] b=parseHex(p.getString("hex"));
   if(off<0||off+b.length>out.length)throw new IOException("Patch at offset "+off+" is outside the file ("+out.length+" bytes)");System.arraycopy(b,0,out,(int)off,b.length);}
  return out;
 }
 static JSONObject hexPatch(Host e,JSONObject a)throws Exception{
  JSONArray patches=a.getJSONArray("patches");String archive=a.optString("archive");
  if(!archive.isEmpty()){
   File src=new File(archive);String entry=a.getString("entry");byte[] data=FileOps.zipEntry(src,entry,MAX_HEX);
   Map<String,byte[]> repl=new HashMap<>();repl.put(entry,applyPatches(data,patches));
   return publish(e,src,repl,Collections.<String>emptySet(),"-patched",a.optBoolean("sign",true));
  }
  File f=new File(a.getString("path"));if(!f.isFile())throw new IOException("File not found");
  long size=f.length();for(int i=0;i<patches.length();i++){JSONObject p=patches.getJSONObject(i);if(p.getLong("offset")<0||p.getLong("offset")+parseHex(p.getString("hex")).length>size)throw new IOException("Patch is outside the file");}
  File bak=new File(f.getPath()+".bak");if(!bak.exists())Files.copy(f.toPath(),bak.toPath());
  try(RandomAccessFile r=new RandomAccessFile(f,"rw")){for(int i=0;i<patches.length();i++){JSONObject p=patches.getJSONObject(i);r.seek(p.getLong("offset"));r.write(parseHex(p.getString("hex")));}}
  e.record("Hex patched "+f.getName());
  return new JSONObject().put("path",f.getPath()).put("backup",bak.getPath());
 }

 // ---------------------------------------------------------------- project folders (apktool-style, XML level)
 static boolean isXmlEntry(String n){return n.equals("AndroidManifest.xml")||(n.startsWith("res/")&&n.endsWith(".xml"));}
 static boolean isSignature(String n){return n.matches("(?i)META-INF/[^/]+\\.(SF|RSA|DSA|EC)")||n.equalsIgnoreCase("META-INF/MANIFEST.MF");}
 static File safeChild(File root,String name)throws IOException{
  File f=new File(root,name);String rc=root.getCanonicalPath()+File.separator;if(!f.getCanonicalPath().startsWith(rc))throw new IOException("Unsafe path in archive: "+name);return f;
 }
 static JSONObject projectDecode(JSONObject a)throws Exception{
  File apk=new File(a.getString("path")),dest=FileOps.child(new File(a.getString("destination")),a.getString("name"));
  if(dest.exists())throw new IOException("Folder already exists");if(!dest.mkdirs())throw new IOException("Cannot create the project folder");
  JSONArray xml=new JSONArray();int files=0,failed=0;long total=0;
  try(ZipFile z=new ZipFile(apk)){
   Enumeration<? extends ZipEntry> en=z.entries();
   while(en.hasMoreElements()){
    ZipEntry ze=en.nextElement();String n=ze.getName();if(ze.isDirectory()||isSignature(n))continue;
    if(++files>20000)throw new IOException("Too many files");
    File out=safeChild(dest,n);out.getParentFile().mkdirs();byte[] data;
    try(InputStream in=z.getInputStream(ze)){data=readLimited(in,MAX_ENTRY);}
    total+=data.length;if(total>2L*1024*1024*1024)throw new IOException("Project is too large");
    if(isXmlEntry(n)&&Axml.isBinary(data)){
     try{String text=new Axml().decode(data);Files.write(out.toPath(),text.getBytes(StandardCharsets.UTF_8));xml.put(n);continue;}catch(Exception ex){failed++;}
    }
    Files.write(out.toPath(),data);
   }
  }
  Files.write(new File(dest,".chproject.json").toPath(),new JSONObject().put("source",apk.getPath()).put("xml",xml).toString(2).getBytes(StandardCharsets.UTF_8));
  return new JSONObject().put("path",dest.getPath()).put("files",files).put("xmlDecoded",xml.length()).put("xmlKeptBinary",failed);
 }
 static byte[] readLimited(InputStream in,long limit)throws IOException{
  ByteArrayOutputStream o=new ByteArrayOutputStream();byte[] buf=new byte[65536];int n;long t=0;
  while((n=in.read(buf))>0){t+=n;if(t>limit)throw new IOException("Entry is too large");o.write(buf,0,n);}return o.toByteArray();
 }
 static JSONObject projectBuild(Host e,JSONObject a)throws Exception{
  File dir=new File(a.getString("folder"));File meta=new File(dir,".chproject.json");
  if(!meta.isFile())throw new IOException("This folder was not created by Decode project");
  JSONObject m=new JSONObject(new String(FileOps.read(meta,1<<20),StandardCharsets.UTF_8));File src=new File(m.getString("source"));
  if(!src.isFile())throw new IOException("The original APK is needed to rebuild but was not found: "+src);
  Set<String> xml=new HashSet<>();JSONArray xa=m.getJSONArray("xml");for(int i=0;i<xa.length();i++)xml.add(xa.getString(i));
  Map<String,byte[]> repl=new LinkedHashMap<>();Set<String> removals=new HashSet<>();Set<String> present=new HashSet<>();int[] count={0};
  walk(dir,dir,present,count);
  try(ZipFile z=new ZipFile(src)){
   for(String n:present){
    byte[] now=Files.readAllBytes(safeChild(dir,n).toPath());ZipEntry ze=z.getEntry(n);
    if(ze==null){repl.put(n,now);continue;}
    byte[] orig;try(InputStream in=z.getInputStream(ze)){orig=readLimited(in,MAX_ENTRY);}
    if(xml.contains(n)){
     Axml ax=new Axml();String before=ax.decode(orig);String text=new String(now,StandardCharsets.UTF_8);
     if(!text.equals(before)){try{repl.put(n,ax.encode(text));}catch(Exception ex){throw new IOException("Cannot encode "+n+": "+ex.getMessage());}}
    }else if(!Arrays.equals(orig,now))repl.put(n,now);
   }
   Enumeration<? extends ZipEntry> en=z.entries();while(en.hasMoreElements()){ZipEntry ze=en.nextElement();String n=ze.getName();if(!ze.isDirectory()&&!isSignature(n)&&!present.contains(n))removals.add(n);}
  }
  if(repl.isEmpty()&&removals.isEmpty())throw new IOException("No changes in the project folder");
  File outDir=new File(a.optString("destination",outDir(e,src).getPath()));
  File tmp=File.createTempFile(".project-",".tmp",outDir);
  try{
   FileOps.rewriteZip(src,tmp,repl,removals);
   File out=unique(outDir,a.optString("name",strip(src.getName())+"-rebuilt"),".apk");
   if(a.optBoolean("sign",true))e.sign(tmp,out);else FileOps.replace(tmp,out);
   e.record("Built "+out.getName());
   return new JSONObject().put("path",out.getPath()).put("changed",repl.size()).put("removed",removals.size()).put("signed",a.optBoolean("sign",true));
  }finally{tmp.delete();}
 }
 static void walk(File root,File dir,Set<String> out,int[] count)throws IOException{
  File[] fs=dir.listFiles();if(fs==null)return;
  for(File f:fs){
   if(Files.isSymbolicLink(f.toPath()))throw new IOException("Symbolic links are not allowed in a project");
   if(f.isDirectory())walk(root,f,out,count);
   else{String rel=root.toPath().relativize(f.toPath()).toString().replace(File.separatorChar,'/');if(rel.equals(".chproject.json"))continue;if(++count[0]>20000)throw new IOException("Too many files");out.add(rel);}
  }
 }

 // ---------------------------------------------------------------- resources.arsc strings (ARSCLib)
 static com.reandroid.arsc.chunk.TableBlock loadTable(File apk)throws Exception{
  byte[] b=FileOps.zipEntry(apk,"resources.arsc",MAX_ENTRY);
  return com.reandroid.arsc.chunk.TableBlock.load(new ByteArrayInputStream(b));
 }
 static JSONObject arscStrings(JSONObject a)throws Exception{
  com.reandroid.arsc.chunk.TableBlock t=loadTable(new File(a.getString("path")));
  com.reandroid.arsc.pool.StringPool<?> pool=t.getStringPool();String q=a.optString("query","").toLowerCase(Locale.ROOT);int limit=Math.min(500,a.optInt("limit",200));
  JSONArray out=new JSONArray();int size=pool.size();
  for(int i=0;i<size&&out.length()<limit;i++){String s=pool.get(i).get();if(s==null)s="";if(!a.optBoolean("all")&&s.startsWith("res/"))continue;if(q.isEmpty()||s.toLowerCase(Locale.ROOT).contains(q))out.put(new JSONObject().put("index",i).put("text",s));}
  return new JSONObject().put("total",size).put("items",out);
 }
 static JSONObject arscReplace(Host e,JSONObject a)throws Exception{
  File src=new File(a.getString("path"));com.reandroid.arsc.chunk.TableBlock t=loadTable(src);
  com.reandroid.arsc.pool.StringPool<?> pool=t.getStringPool();JSONArray changes=a.getJSONArray("changes");int n=0;
  for(int i=0;i<changes.length();i++){
   JSONObject c=changes.getJSONObject(i);com.reandroid.arsc.item.StringItem item=pool.get(c.getInt("index"));if(item==null)throw new IOException("String "+c.getInt("index")+" does not exist");
   String text=c.getString("text");if(!text.equals(item.get())){item.set(text);n++;}
  }
  if(n==0)throw new IOException("Nothing to change");
  t.refresh();Map<String,byte[]> repl=new HashMap<>();repl.put("resources.arsc",t.getBytes());
  JSONObject r=publish(e,src,repl,Collections.<String>emptySet(),"-strings",a.optBoolean("sign",true));return r.put("changed",n);
 }

 // ---------------------------------------------------------------- signing key
 static File keyFile(File filesDir){return new File(new File(filesDir,"signing"),"key.p12");}
 static File keyMeta(File filesDir){return new File(new File(filesDir,"signing"),"key.json");}
 static File filesDir;
 static void loadKey(File dir){
  filesDir=dir;
  try{
   File k=keyFile(dir),m=keyMeta(dir);if(!k.isFile()||!m.isFile())return;
   JSONObject j=new JSONObject(new String(Files.readAllBytes(m.toPath()),StandardCharsets.UTF_8));
   ApkSigning.useCustom(Files.readAllBytes(k.toPath()),j.getString("storePass").toCharArray(),j.getString("keyPass").toCharArray(),j.optString("alias",null));
  }catch(Exception ignored){ApkSigning.clearCustom();}
 }
 static JSONObject ksStatus()throws Exception{
  byte[] p12=ApkSigning.customP12;if(p12==null)return new JSONObject().put("custom",false).put("name","Development key (public, bundled)");
  KeyStore ks=KeyStore.getInstance("PKCS12");ks.load(new ByteArrayInputStream(p12),ApkSigning.customPass);String alias=ApkSigning.firstKey(ks);
  X509Certificate c=(X509Certificate)ks.getCertificate(alias);
  return new JSONObject().put("custom",true).put("alias",alias).put("subject",c.getSubjectX500Principal().getName()).put("validTo",c.getNotAfter().getTime()).put("sha256",hex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded())));
 }
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}
 static void install(byte[] p12,char[] storePass,char[] keyPass,String alias)throws Exception{
  if(filesDir==null)throw new IOException("Not initialised");
  KeyStore ks=KeyStore.getInstance("PKCS12");ks.load(new ByteArrayInputStream(p12),storePass);
  String use=alias!=null&&!alias.isEmpty()&&ks.isKeyEntry(alias)?alias:ApkSigning.firstKey(ks);
  Key key=ks.getKey(use,keyPass);if(!(key instanceof PrivateKey))throw new IOException("Wrong key password or no private key");
  if(!(ks.getCertificate(use) instanceof X509Certificate))throw new IOException("Keystore has no certificate");
  File dir=keyFile(filesDir).getParentFile();dir.mkdirs();
  FileOps.writeAtomic(keyFile(filesDir),p12,false);
  FileOps.writeAtomic(keyMeta(filesDir),new JSONObject().put("storePass",new String(storePass)).put("keyPass",new String(keyPass)).put("alias",use).toString().getBytes(StandardCharsets.UTF_8),false);
  ApkSigning.useCustom(p12,storePass,keyPass,use);
 }
 static JSONObject ksImport(Host e,JSONObject a)throws Exception{
  File f=new File(a.getString("path"));if(!f.isFile())throw new IOException("Keystore file not found");
  String pass=a.getString("password"),kp=a.optString("keyPassword","");if(kp.isEmpty())kp=pass;
  try{install(FileOps.read(f,8L*1024*1024),pass.toCharArray(),kp.toCharArray(),a.optString("alias",""));}
  catch(IOException|GeneralSecurityException ex){throw new IOException("Cannot use this keystore (PKCS12 .p12/.pfx/.keystore only): "+ex.getMessage());}
  e.record("Imported signing key");return ksStatus();
 }
 static JSONObject ksGenerate(Host e,JSONObject a)throws Exception{
  String alias=a.optString("alias","key0"),pass=a.getString("password"),cn=a.optString("name","Developer");int years=Math.max(1,Math.min(50,a.optInt("years",30)));
  if(pass.length()<6)throw new IOException("Password must have at least 6 characters");
  byte[] p12=generateP12(alias,pass.toCharArray(),cn,years);
  install(p12,pass.toCharArray(),pass.toCharArray(),alias);
  JSONObject r=ksStatus();
  String dest=a.optString("exportTo","");
  if(!dest.isEmpty()){File d=unique(new File(dest),"my-signing-key",".p12");Files.write(d.toPath(),p12);r.put("exported",d.getPath());}
  e.record("Generated signing key");return r;
 }
 static JSONObject ksExport(Host e,JSONObject a)throws Exception{
  if(ApkSigning.customP12==null)throw new IOException("No custom key is installed");
  File d=unique(new File(a.getString("destination")),a.optString("name","my-signing-key"),".p12");Files.write(d.toPath(),ApkSigning.customP12);
  return new JSONObject().put("path",d.getPath()).put("note","Keep this file and its password safe. Without them you cannot update apps signed with it.");
 }
 static JSONObject ksReset(Host e)throws Exception{
  if(filesDir!=null){keyFile(filesDir).delete();keyMeta(filesDir).delete();}ApkSigning.clearCustom();e.record("Signing key reset to development key");return ksStatus();
 }

 // ---- self-signed certificate (hand-built DER so no extra library is needed)
 static byte[] generateP12(String alias,char[] pass,String cn,int years)throws Exception{
  KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048,new SecureRandom());KeyPair kp=g.generateKeyPair();
  X509Certificate cert=selfSigned(kp,cn,years);
  KeyStore ks=KeyStore.getInstance("PKCS12");ks.load(null,null);ks.setKeyEntry(alias,kp.getPrivate(),pass,new java.security.cert.Certificate[]{cert});
  ByteArrayOutputStream o=new ByteArrayOutputStream();ks.store(o,pass);return o.toByteArray();
 }
 static X509Certificate selfSigned(KeyPair kp,String cn,int years)throws Exception{
  byte[] sigAlg=der(0x30,cat(oid("1.2.840.113549.1.1.11"),new byte[]{5,0}));
  byte[] name=der(0x30,der(0x31,der(0x30,cat(oid("2.5.4.3"),der(0x0C,cn.getBytes(StandardCharsets.UTF_8))))));
  Calendar from=Calendar.getInstance(TimeZone.getTimeZone("UTC"));from.add(Calendar.DAY_OF_YEAR,-1);Calendar to=(Calendar)from.clone();to.add(Calendar.YEAR,years);
  byte[] serial=new byte[8];new SecureRandom().nextBytes(serial);serial[0]&=0x7f;serial[0]|=0x40;
  byte[] tbs=der(0x30,cat(der(0xA0,der(0x02,new byte[]{2})),der(0x02,serial),sigAlg,name,der(0x30,cat(time(from),time(to))),name,kp.getPublic().getEncoded()));
  Signature s=Signature.getInstance("SHA256withRSA");s.initSign(kp.getPrivate());s.update(tbs);byte[] sig=s.sign();
  byte[] bits=new byte[sig.length+1];System.arraycopy(sig,0,bits,1,sig.length);
  byte[] certDer=der(0x30,cat(tbs,sigAlg,der(0x03,bits)));
  return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certDer));
 }
 static byte[] time(Calendar c){
  int y=c.get(Calendar.YEAR);String f=String.format("%04d%02d%02d%02d%02d%02dZ",y,c.get(Calendar.MONTH)+1,c.get(Calendar.DAY_OF_MONTH),c.get(Calendar.HOUR_OF_DAY),c.get(Calendar.MINUTE),c.get(Calendar.SECOND));
  return y<2050?der(0x17,f.substring(2).getBytes(StandardCharsets.US_ASCII)):der(0x18,f.getBytes(StandardCharsets.US_ASCII));
 }
 static byte[] cat(byte[]... p){ByteArrayOutputStream o=new ByteArrayOutputStream();for(byte[] b:p)o.write(b,0,b.length);return o.toByteArray();}
 static byte[] der(int tag,byte[] body){
  ByteArrayOutputStream o=new ByteArrayOutputStream();o.write(tag);int n=body.length;
  if(n<128)o.write(n);else if(n<256){o.write(0x81);o.write(n);}else if(n<65536){o.write(0x82);o.write(n>>8);o.write(n);}else{o.write(0x83);o.write(n>>16);o.write(n>>8);o.write(n);}
  o.write(body,0,body.length);return o.toByteArray();
 }
 static byte[] oid(String dotted){
  String[] p=dotted.split("\\.");ByteArrayOutputStream o=new ByteArrayOutputStream();o.write(Integer.parseInt(p[0])*40+Integer.parseInt(p[1]));
  for(int i=2;i<p.length;i++){long v=Long.parseLong(p[i]);byte[] t=new byte[10];int n=0;t[n++]=(byte)(v&0x7f);v>>=7;while(v>0){t[n++]=(byte)((v&0x7f)|0x80);v>>=7;}for(int j=n-1;j>=0;j--)o.write(t[j]);}
  return der(0x06,o.toByteArray());
 }
}
