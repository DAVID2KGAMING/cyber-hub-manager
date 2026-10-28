package david.manager;

import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.dexbacked.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.writer.pool.DexPool;

/**
 * Adds a self-contained runtime guard to an APK: an Application subclass that checks the signing
 * certificate, looks for root, debuggers, emulators, Frida/Xposed, tapjacking and MITM proxies, can
 * verify DEX/resources.arsc/assets integrity, enforce an install source or an expiry date, and can
 * force allowBackup/debuggable off. No existing class is touched; only AndroidManifest.xml and one
 * new DEX class are added. The guard's class name, method names, meta-data keys, and every literal
 * "signal" string (root paths, Frida markers, proc paths, ...) are randomized/obfuscated per call, so
 * two protected APKs never share a recognizable fingerprint and a plain `strings` dump on the DEX
 * doesn't reveal what is being checked.
 * Scope: only APKs that do not already declare android:application/android:name (no existing
 * custom Application subclass) are supported in this version.
 */
final class ApkProtect {
 private ApkProtect(){}

 static JSONObject info(File apk)throws Exception{
  String xml=new Axml().decode(ApkTools.manifestBytes(apk));
  Matcher am=Pattern.compile("<application\\b[^>]*>").matcher(xml);String atag=am.find()?am.group():"";
  String existing=ApkTools.attr(atag,"android:name");
  return new JSONObject().put("package",ApkTools.attr(find(xml),"package")).put("hasCustomApplication",!existing.isEmpty()).put("existingApplication",existing);
 }
 static String find(String xml){Matcher m=Pattern.compile("<manifest\\b[^>]*>").matcher(xml);return m.find()?m.group():"";}

 static final java.util.regex.Pattern DATE=Pattern.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}");

 // ---------------------------------------------------------------- randomized naming/obfuscation
 static final SecureRandom RNG=new SecureRandom();
 static String randIdent(int len){
  String first="abcdefghijklmnopqrstuvwxyz",rest="abcdefghijklmnopqrstuvwxyz0123456789";
  StringBuilder s=new StringBuilder();s.append(first.charAt(RNG.nextInt(first.length())));
  for(int i=1;i<len;i++)s.append(rest.charAt(RNG.nextInt(rest.length())));
  return s.toString();
 }
 /** Per-protect randomized identifiers and the XOR key, so no two protected APKs look alike. */
 static final class Names{
  String cls,mCheck,mFail,mReadEntry,mSha256,mHex,mDecode,kEntries,kHashes,kArsc,kAssets;
  int key;
 }
 static Names randomNames(){
  Names n=new Names();
  n.cls=randIdent(8);n.mCheck=randIdent(5);n.mFail=randIdent(4);n.mReadEntry=randIdent(6);n.mSha256=randIdent(5);n.mHex=randIdent(4);n.mDecode=randIdent(4);
  n.kEntries=randIdent(7);n.kHashes=randIdent(7);n.kArsc=randIdent(7);n.kAssets=randIdent(7);
  n.key=1+RNG.nextInt(254);
  return n;
 }
 static String xorB64(String plain,int key){
  byte[] p=plain.getBytes(StandardCharsets.UTF_8);byte[] o=new byte[p.length];
  for(int i=0;i<p.length;i++)o[i]=(byte)(p[i]^key);
  return Base64.getEncoder().encodeToString(o);
 }
 /** Source text for a call that decodes one literal at runtime, e.g. d7f("YQrPtg==",173). */
 static String dc(Names n,String plain){return n.mDecode+"(\""+xorB64(plain,n.key)+"\","+n.key+")";}
 /** Same, for several items packed with '|' and split back out at runtime. */
 static String dcJoined(Names n,String... items){return dc(n,String.join("|",items));}

 static JSONObject run(ApkTools.Host e,JSONObject a)throws Exception{
  File src=new File(a.getString("path"));if(!src.getName().toLowerCase(Locale.ROOT).endsWith(".apk"))throw new IOException("Choose an APK file");
  boolean sig=a.optBoolean("signatureCheck",true),root=a.optBoolean("rootCheck",true),dbg=a.optBoolean("debuggerCheck",true);
  boolean emulator=a.optBoolean("emulatorCheck",false),frida=a.optBoolean("fridaCheck",false),screenshot=a.optBoolean("screenshotBlock",false);
  boolean installSrc=a.optBoolean("installSourceCheck",false),expiry=a.optBoolean("expiryCheck",false),integrity=a.optBoolean("integrityCheck",false);
  boolean disableBackup=a.optBoolean("disableBackup",false),forceNonDebuggable=a.optBoolean("forceNonDebuggable",false);
  boolean tapjacking=a.optBoolean("tapjackingCheck",false),mitm=a.optBoolean("mitmCheck",false);
  String installPkgsRaw=a.optString("installSourcePackages","").trim();
  List<String> installPkgs=new ArrayList<>();
  if(installSrc){
   if(installPkgsRaw.isEmpty())throw new IOException("Enter at least one allowed installer package (e.g. com.android.vending)");
   for(String p:installPkgsRaw.split(",")){String t=p.trim();if(!t.isEmpty()){if(!t.matches("[A-Za-z][A-Za-z0-9_.]*"))throw new IOException("Not a valid package name: "+t);installPkgs.add(t);}}
  }
  long expiryMillis=0;
  if(expiry){
   String d=a.optString("expiryDate","").trim();if(!DATE.matcher(d).matches())throw new IOException("Enter the expiry date (YYYY-MM-DD)");
   java.text.SimpleDateFormat f=new java.text.SimpleDateFormat("yyyy-MM-dd");f.setTimeZone(TimeZone.getTimeZone("UTC"));f.setLenient(false);
   try{expiryMillis=f.parse(d).getTime();}catch(Exception ex){throw new IOException("Not a valid date: "+d);}
  }
  if(!sig&&!root&&!dbg&&!emulator&&!frida&&!screenshot&&!installSrc&&!expiry&&!integrity&&!disableBackup&&!forceNonDebuggable&&!tapjacking&&!mitm)throw new IOException("Choose at least one protection");

  Axml ax=new Axml();String xml=ax.decode(ApkTools.manifestBytes(src));
  Matcher rm=Pattern.compile("<manifest\\b[^>]*>").matcher(xml);if(!rm.find())throw new IOException("AndroidManifest.xml has no <manifest> element");
  String pkg=ApkTools.attr(rm.group(),"package");if(pkg.isEmpty())throw new IOException("Cannot read the package name");
  Matcher am=Pattern.compile("<application\\b[^>]*>").matcher(xml);if(!am.find())throw new IOException("AndroidManifest.xml has no <application> element");
  String appTag=am.group(),existingName=ApkTools.attr(appTag,"android:name");
  if(!existingName.isEmpty())throw new IOException("This APK already has a custom Application class ("+existingName+"). Protect APK does not support chaining onto it yet.");

  // Expected signing certificate: whatever ApkTools.publish() will actually sign with.
  byte[] certSha256=sig?e.devSigningCert():null;

  Names gn=randomNames();
  String guardBin=pkg.replace('.', '/')+"/"+gn.cls;
  String javaPkg=pkg;
  String guardType="L"+guardBin+";";
  File apiJar=e.androidApiJar();

  // Pick the first classes*.dex entry to host the new class (any would do; app loads them all).
  String dexEntry=firstDexEntry(src);
  byte[] dexBytes=FileOps.zipEntry(src,dexEntry,256L*1024*1024);

  // Content the guard does NOT change can be hashed straight from the source APK — no circularity.
  String arscHash=null;try{arscHash=sha256Hex(FileOps.zipEntry(src,"resources.arsc",256L*1024*1024));}catch(Exception ignored){}
  String assetsHash=hashAssets(src);

  // Multidex: every classes*.dex is watched, not just the one that hosts the guard. The other dex
  // files are unmodified by us, so their hashes are known upfront; only the host dex is circular.
  List<String> allDex=integrity?allDexEntries(src):Collections.singletonList(dexEntry);
  LinkedHashMap<String,String> dexHashes=new LinkedHashMap<>();
  if(integrity)for(String d:allDex)if(!d.equals(dexEntry))dexHashes.put(d,sha256Hex(FileOps.zipEntry(src,d,256L*1024*1024)));

  // The host DEX's own hash cannot be embedded inside itself (a file cannot contain its exact hash
  // of itself). Build the guard once — it only READS its expected hashes from manifest meta-data at
  // runtime, never from a baked-in constant — then hash the finished DEX and store that outside it.
  byte[] mergedDex=buildMergedDex(src,dexEntry,dexBytes,guardType,guardBin,javaPkg,certSha256,root,dbg,emulator,frida,screenshot,installSrc,installPkgs,expiry,expiryMillis,integrity,tapjacking,mitm,gn,apiJar,e.workspace());
  if(integrity)dexHashes.put(dexEntry,sha256Hex(mergedDex));

  String newAppTag=appTag.substring(0,appTag.length()-1)+" android:name=\""+ApkTools.escape("."+gn.cls)+"\">";
  if(disableBackup)newAppTag=ApkTools.setOrAddAttr(newAppTag,"android:allowBackup","false");
  if(forceNonDebuggable)newAppTag=ApkTools.setOrAddAttr(newAppTag,"android:debuggable","false");
  StringBuilder meta=new StringBuilder();
  if(integrity){
   StringBuilder entries=new StringBuilder(),hashes=new StringBuilder();
   for(String d:allDex){if(entries.length()>0){entries.append(',');hashes.append(',');}entries.append(d);hashes.append(dexHashes.get(d));}
   meta.append("<meta-data android:name=\"").append(gn.kEntries).append("\" android:value=\"").append(ApkTools.escape(entries.toString())).append("\"/>");
   meta.append("<meta-data android:name=\"").append(gn.kHashes).append("\" android:value=\"").append(hashes).append("\"/>");
   if(arscHash!=null)meta.append("<meta-data android:name=\"").append(gn.kArsc).append("\" android:value=\"").append(arscHash).append("\"/>");
   meta.append("<meta-data android:name=\"").append(gn.kAssets).append("\" android:value=\"").append(assetsHash).append("\"/>");
  }
  String editedXml=xml.substring(0,am.start())+newAppTag+meta+xml.substring(am.end());

  Map<String,byte[]> repl=new HashMap<>();
  repl.put("AndroidManifest.xml",ax.encode(editedXml));
  repl.put(dexEntry,mergedDex);
  JSONObject r=ApkTools.publish(e,src,repl,Collections.<String>emptySet(),"-protected",true);
  return r.put("checks",new JSONObject().put("signature",sig).put("root",root).put("debugger",dbg).put("emulator",emulator).put("frida",frida).put("screenshotBlock",screenshot).put("installSource",installSrc).put("expiry",expiry).put("integrity",integrity).put("dexCount",allDex.size()).put("disableBackup",disableBackup).put("forceNonDebuggable",forceNonDebuggable).put("tapjacking",tapjacking).put("mitm",mitm)).put("class",javaPkg+"."+gn.cls);
 }
 static String sha256Hex(byte[] data)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(data));}
 /** Order-independent-by-name, content-based hash of everything under assets/ in an APK. Stable even with zero assets. */
 static String hashAssets(File apk)throws Exception{
  TreeMap<String,byte[]> sorted=new TreeMap<>();
  try(ZipFile z=new ZipFile(apk)){
   Enumeration<? extends ZipEntry> en=z.entries();
   while(en.hasMoreElements()){
    ZipEntry ze=en.nextElement();if(ze.isDirectory()||!ze.getName().startsWith("assets/"))continue;
    try(InputStream in=z.getInputStream(ze)){sorted.put(ze.getName(),ApkTools.readLimited(in,64L*1024*1024));}
   }
  }
  MessageDigest md=MessageDigest.getInstance("SHA-256");
  for(Map.Entry<String,byte[]> en:sorted.entrySet()){md.update(en.getKey().getBytes(StandardCharsets.UTF_8));md.update((byte)0);md.update(en.getValue());}
  return hex(md.digest());
 }
 static byte[] buildMergedDex(File src,String dexEntry,byte[] dexBytes,String guardType,String guardBin,String javaPkg,byte[] certSha256,boolean root,boolean dbg,boolean emulator,boolean frida,boolean screenshot,boolean installSrc,List<String> installPkgs,boolean expiry,long expiryMillis,boolean integrity,boolean tapjacking,boolean mitm,Names gn,File apiJar,File workspace)throws Exception{
  String source=guardSource(javaPkg,certSha256,root,dbg,emulator,frida,screenshot,installSrc,installPkgs,expiry,expiryMillis,integrity,tapjacking,mitm,gn);
  List<ClassDef> guardClasses=compileStandalone(guardType,source,apiJar,workspace);
  File tmpDex=File.createTempFile(".guard-src-",".dex",workspace);
  try{
   java.nio.file.Files.write(tmpDex.toPath(),dexBytes);
   DexBackedDexFile original=DexFileFactory.loadDexFile(tmpDex,Opcodes.getDefault());
   if(original.getClasses().stream().anyMatch(c->c.getType().equals(guardType)))throw new IOException("A class named "+gn.cls+" already exists in this package. Protect APK cannot add its guard.");
   List<ClassDef> all=new ArrayList<>();for(ClassDef c:original.getClasses())all.add(c);all.addAll(guardClasses);
   File out=File.createTempFile(".guard-out-",".dex",workspace);
   try{DexPool.writeTo(out.getPath(),new ImmutableDexFile(original.getOpcodes(),all));return java.nio.file.Files.readAllBytes(out.toPath());}finally{out.delete();}
  }finally{tmpDex.delete();}
 }

 static String firstDexEntry(File apk)throws Exception{
  try(ZipFile z=new ZipFile(apk)){
   if(z.getEntry("classes.dex")!=null)return "classes.dex";
   Enumeration<? extends ZipEntry> en=z.entries();
   while(en.hasMoreElements()){String n=en.nextElement().getName();if(n.matches("classes\\d*\\.dex"))return n;}
  }
  throw new IOException("No DEX found in this APK");
 }
 /** Every classes*.dex entry in the APK (multidex-safe), sorted so the watch list is deterministic. */
 static List<String> allDexEntries(File apk)throws Exception{
  TreeSet<String> names=new TreeSet<>((a,b)->a.length()!=b.length()?a.length()-b.length():a.compareTo(b));
  try(ZipFile z=new ZipFile(apk)){
   Enumeration<? extends ZipEntry> en=z.entries();
   while(en.hasMoreElements()){String n=en.nextElement().getName();if(n.matches("classes\\d*\\.dex"))names.add(n);}
  }
  if(names.isEmpty())throw new IOException("No DEX found in this APK");
  return new ArrayList<>(names);
 }

 /** Compile one standalone top-level class (plus any nested/anonymous classes it defines) with ECJ,
  * convert to DEX with the bundled dx. No project stubs: the guard only uses the public Android API. */
 static List<ClassDef> compileStandalone(String type,String text,File platform,File workspace)throws Exception{
  if(!platform.isFile())throw new IOException("Compiler API library is missing");
  File work=new File(workspace,"guard-"+UUID.randomUUID());if(!work.mkdirs())throw new IOException("Cannot create compiler workspace");
  try{
   String binary=type.substring(1,type.length()-1),simple=binary.substring(binary.lastIndexOf('/')+1);
   File source=new File(work,simple+".java"),output=new File(work,"classes");output.mkdirs();
   FileOps.writeAtomic(source,text.getBytes(StandardCharsets.UTF_8),false);
   StringWriter log=new StringWriter();PrintWriter messages=new PrintWriter(log);
   // -g:none: no debug info at all — local variable and parameter names would otherwise sit in the
   // DEX as plain text, which could leak a careless identifier the same way a literal string would.
   boolean ok=org.eclipse.jdt.core.compiler.batch.BatchCompiler.compile(new String[]{"-1.8","-proc:none","-g:none","-nowarn","-encoding","UTF-8","-maxProblems","30","-bootclasspath",platform.getPath(),"-d",output.getPath(),source.getPath()},messages,messages,null);
   messages.flush();if(!ok)throw new IOException("Guard class failed to compile:\n"+log);
   File classJar=new File(work,"compiled.jar");List<File> compiled=new ArrayList<>();collectClasses(output,compiled);
   if(compiled.isEmpty())throw new IOException("The compiler did not emit any classes");
   try(ZipOutputStream zip=new ZipOutputStream(new FileOutputStream(classJar))){
    for(File f:compiled){String name=output.toPath().relativize(f.toPath()).toString().replace(File.separatorChar,'/');zip.putNextEntry(new ZipEntry(name));zip.write(FileOps.read(f,8L*1024*1024));zip.closeEntry();}
   }
   File dex=new File(work,"compiled.dex");
   ByteArrayOutputStream dxLog=new ByteArrayOutputStream();PrintStream dxOut=new PrintStream(dxLog,true,"UTF-8");
   com.android.dx.command.dexer.DxContext context=new com.android.dx.command.dexer.DxContext(dxOut,dxOut);
   int result=com.android.dx.command.dexer.CyberCompiler.compile(context,classJar.getPath(),dex.getPath());
   if(result!=0||!dex.isFile())throw new IOException("Guard class failed to convert to DEX:\n"+dxLog.toString("UTF-8"));
   DexBackedDexFile parsed=DexFileFactory.loadDexFile(dex,Opcodes.getDefault());
   String family=type.substring(0,type.length()-1)+"$"; // Lpkg/Name$ — matches Lpkg/Name$1; nested/anonymous classes
   List<ClassDef> family_=new ArrayList<>();boolean found=false;
   for(ClassDef c:parsed.getClasses()){
    if(c.getType().equals(type)){found=true;family_.add(ImmutableClassDef.of(c));}
    else if(c.getType().startsWith(family))family_.add(ImmutableClassDef.of(c));
   }
   if(!found)throw new IOException("Compiled class not found: "+type);
   return family_;
  }finally{FileOps.deleteTree(work);}
 }
 static void collectClasses(File dir,List<File> out){File[] fs=dir.listFiles();if(fs==null)return;for(File f:fs)if(f.isDirectory())collectClasses(f,out);else if(f.getName().endsWith(".class"))out.add(f);}

 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}

 static String guardSource(String pkg,byte[] certSha256,boolean root,boolean dbg,boolean emulator,boolean frida,boolean screenshot,boolean installSrc,List<String> installPkgs,boolean expiry,long expiryMillis,boolean integrity,boolean tapjacking,boolean mitm,Names n){
  StringBuilder b=new StringBuilder();
  b.append("package ").append(pkg).append(";\n");
  b.append("import android.app.Application;import android.app.Activity;import android.content.pm.*;import android.content.Context;import android.os.Bundle;import android.view.WindowManager;import java.security.MessageDigest;import java.security.KeyStore;import java.io.*;import java.util.*;\n");
  b.append("public final class ").append(n.cls).append(" extends Application {\n");
  b.append(" @Override public void onCreate(){super.onCreate();try{").append(n.mCheck).append("(this);}catch(Throwable t){").append(n.mFail).append("();}\n");
  if(screenshot||tapjacking){
   b.append("  registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks(){\n");
   b.append("   public void onActivityCreated(Activity a,Bundle s){try{\n");
   if(screenshot)b.append("    a.getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,WindowManager.LayoutParams.FLAG_SECURE);\n");
   if(tapjacking)b.append("    a.getWindow().getDecorView().setFilterTouchesWhenObscured(true);\n");
   b.append("   }catch(Throwable t){}}\n");
   b.append("   public void onActivityStarted(Activity a){}\n   public void onActivityResumed(Activity a){}\n   public void onActivityPaused(Activity a){}\n   public void onActivityStopped(Activity a){}\n   public void onActivitySaveInstanceState(Activity a,Bundle s){}\n   public void onActivityDestroyed(Activity a){}\n");
   b.append("  });\n");
  }
  b.append(" }\n");
  b.append(" static void ").append(n.mCheck).append("(Context c)throws Exception{\n");
  if(certSha256!=null){
   b.append("  String expected=\"").append(hex(certSha256)).append("\";\n");
   b.append("  PackageInfo info=c.getPackageManager().getPackageInfo(c.getPackageName(),PackageManager.GET_SIGNATURES);\n");
   b.append("  boolean matched=false;MessageDigest md=MessageDigest.getInstance(\"SHA-256\");\n");
   b.append("  for(Signature s:info.signatures){md.reset();byte[] d=md.digest(s.toByteArray());StringBuilder h=new StringBuilder();for(byte x:d)h.append(String.format(\"%02x\",x&255));if(h.toString().equals(expected))matched=true;}\n");
   b.append("  if(!matched)").append(n.mFail).append("();\n");
  }
  if(root){
   b.append("  String[] paths=").append(dcJoined(n,"/system/app/Superuser.apk","/sbin/su","/system/bin/su","/system/xbin/su","/data/local/xbin/su","/data/local/bin/su","/system/sd/xbin/su","/system/bin/failsafe/su","/data/local/su","/su/bin/su","/system/bin/magisk","/sbin/magisk")).append(".split(\"\\\\|\");\n");
   b.append("  for(String p:paths)if(new File(p).exists())").append(n.mFail).append("();\n");
   b.append("  String tags=android.os.Build.TAGS;if(tags!=null&&tags.contains(").append(dc(n,"test-keys")).append("))").append(n.mFail).append("();\n");
  }
  if(dbg){
   b.append("  if(android.os.Debug.isDebuggerConnected()||android.os.Debug.waitingForDebugger())").append(n.mFail).append("();\n");
   b.append("  try(BufferedReader r=new BufferedReader(new FileReader(").append(dc(n,"/proc/self/status")).append("))){String line;while((line=r.readLine())!=null)if(line.startsWith(").append(dc(n,"TracerPid:")).append(")&&!line.trim().endsWith(\"0\"))").append(n.mFail).append("();}catch(Exception ignored){}\n");
  }
  if(emulator){
   b.append("  String fp=android.os.Build.FINGERPRINT,model=android.os.Build.MODEL,manu=android.os.Build.MANUFACTURER,hw=android.os.Build.HARDWARE,prod=android.os.Build.PRODUCT,brand=android.os.Build.BRAND,dev=android.os.Build.DEVICE;\n");
   b.append("  String[] mk1=").append(dcJoined(n,"generic","unknown","vbox","test-keys")).append(".split(\"\\\\|\");\n");
   b.append("  String[] mk2=").append(dcJoined(n,"google_sdk","Emulator","Android SDK built for")).append(".split(\"\\\\|\");\n");
   b.append("  boolean emu=false;\n");
   b.append("  if(fp!=null)for(String mk:mk1)if(fp.startsWith(mk)||fp.contains(mk))emu=true;\n");
   b.append("  if(model!=null)for(String mk:mk2)if(model.contains(mk))emu=true;\n");
   b.append("  if(manu!=null&&manu.toLowerCase().contains(").append(dc(n,"genymotion")).append("))emu=true;\n");
   b.append("  if(brand!=null&&brand.startsWith(\"generic\")&&dev!=null&&dev.startsWith(\"generic\"))emu=true;\n");
   b.append("  String[] mk3=").append(dcJoined(n,"goldfish","ranchu")).append(".split(\"\\\\|\");\n");
   b.append("  if(hw!=null)for(String mk:mk3)if(hw.contains(mk))emu=true;\n");
   b.append("  if(prod!=null&&prod.contains(").append(dc(n,"sdk")).append("))emu=true;\n");
   b.append("  String[] mk4=").append(dcJoined(n,"/dev/socket/qemud","/dev/qemu_pipe")).append(".split(\"\\\\|\");\n");
   b.append("  for(String qp:mk4)if(new File(qp).exists())emu=true;\n");
   b.append("  if(emu)").append(n.mFail).append("();\n");
  }
  if(frida){
   b.append("  if(new File(").append(dc(n,"/system/framework/XposedBridge.jar")).append(").exists())").append(n.mFail).append("();\n");
   b.append("  String[] mk5=").append(dcJoined(n,"frida","xposed","substrate")).append(".split(\"\\\\|\");\n");
   b.append("  try(BufferedReader r=new BufferedReader(new FileReader(").append(dc(n,"/proc/self/maps")).append("))){String line;while((line=r.readLine())!=null){String low=line.toLowerCase();for(String mk:mk5)if(low.contains(mk))").append(n.mFail).append("();}}catch(Exception ignored){}\n");
  }
  if(installSrc){
   b.append("  String installer;\n");
   b.append("  if(android.os.Build.VERSION.SDK_INT>=30){InstallSourceInfo isi=c.getPackageManager().getInstallSourceInfo(c.getPackageName());installer=isi.getInstallingPackageName();}\n");
   b.append("  else installer=c.getPackageManager().getInstallerPackageName(c.getPackageName());\n");
   b.append("  String[] allowed={");
   for(int i=0;i<installPkgs.size();i++){if(i>0)b.append(',');b.append('"').append(escapeJava(installPkgs.get(i))).append('"');}
   b.append("};\n");
   b.append("  boolean ok=false;if(installer!=null)for(String al:allowed)if(installer.equals(al))ok=true;\n");
   b.append("  if(!ok)").append(n.mFail).append("();\n");
  }
  if(expiry){
   b.append("  if(System.currentTimeMillis()>").append(expiryMillis).append("L)").append(n.mFail).append("();\n");
  }
  if(integrity){
   b.append("  ApplicationInfo ai=c.getPackageManager().getApplicationInfo(c.getPackageName(),PackageManager.GET_META_DATA);\n");
   b.append("  android.os.Bundle gmd=ai.metaData;if(gmd==null)").append(n.mFail).append("();\n");
   b.append("  String dexEntries=gmd.getString(\"").append(n.kEntries).append("\"),dexHashes=gmd.getString(\"").append(n.kHashes).append("\"),expArsc=gmd.getString(\"").append(n.kArsc).append("\"),expAssets=gmd.getString(\"").append(n.kAssets).append("\");\n");
   b.append("  java.util.zip.ZipFile zf=new java.util.zip.ZipFile(ai.sourceDir);\n");
   b.append("  try{\n");
   b.append("   if(dexEntries!=null&&dexHashes!=null){\n");
   b.append("    String[] names=dexEntries.split(\",\"),hashes=dexHashes.split(\",\");\n");
   b.append("    if(names.length!=hashes.length)").append(n.mFail).append("();\n");
   b.append("    for(int i=0;i<names.length;i++)if(!").append(n.mSha256).append("(").append(n.mReadEntry).append("(zf,names[i])).equals(hashes[i]))").append(n.mFail).append("();\n");
   b.append("   }\n");
   b.append("   if(expArsc!=null){if(!").append(n.mSha256).append("(").append(n.mReadEntry).append("(zf,").append(dc(n,"resources.arsc")).append(")).equals(expArsc))").append(n.mFail).append("();}\n");
   b.append("   if(expAssets!=null){\n");
   b.append("    TreeMap<String,byte[]> sorted=new TreeMap<>();java.util.Enumeration<? extends java.util.zip.ZipEntry> en=zf.entries();\n");
   b.append("    String assetsPrefix=").append(dc(n,"assets/")).append(";\n");
   b.append("    while(en.hasMoreElements()){java.util.zip.ZipEntry e2=en.nextElement();if(!e2.isDirectory()&&e2.getName().startsWith(assetsPrefix))sorted.put(e2.getName(),").append(n.mReadEntry).append("(zf,e2.getName()));}\n");
   b.append("    MessageDigest md2=MessageDigest.getInstance(\"SHA-256\");for(Map.Entry<String,byte[]> en2:sorted.entrySet()){md2.update(en2.getKey().getBytes(\"UTF-8\"));md2.update((byte)0);md2.update(en2.getValue());}\n");
   b.append("    if(!").append(n.mHex).append("(md2.digest()).equals(expAssets))").append(n.mFail).append("();\n");
   b.append("   }\n");
   b.append("  }finally{zf.close();}\n");
  }
  if(mitm){
   b.append("  try{\n");
   b.append("   KeyStore caStore=KeyStore.getInstance(").append(dc(n,"AndroidCAStore")).append(");caStore.load(null,null);\n");
   b.append("   java.util.Enumeration<String> aliases=caStore.aliases();\n");
   b.append("   while(aliases.hasMoreElements())if(aliases.nextElement().startsWith(").append(dc(n,"user:")).append("))").append(n.mFail).append("();\n");
   b.append("  }catch(Throwable t){}\n");
  }
  b.append(" }\n");
  if(integrity){
   b.append(" static byte[] ").append(n.mReadEntry).append("(java.util.zip.ZipFile zf,String name)throws IOException{java.util.zip.ZipEntry e2=zf.getEntry(name);if(e2==null)return new byte[0];ByteArrayOutputStream o=new ByteArrayOutputStream();InputStream in=zf.getInputStream(e2);byte[] buf=new byte[65536];int bn;while((bn=in.read(buf))>0)o.write(buf,0,bn);in.close();return o.toByteArray();}\n");
   b.append(" static String ").append(n.mSha256).append("(byte[] d)throws Exception{return ").append(n.mHex).append("(MessageDigest.getInstance(\"SHA-256\").digest(d));}\n");
   b.append(" static String ").append(n.mHex).append("(byte[] d){StringBuilder h=new StringBuilder();for(byte x:d)h.append(String.format(\"%02x\",x&255));return h.toString();}\n");
  }
  b.append(" static String ").append(n.mDecode).append("(String s,int k){byte[] dd=java.util.Base64.getDecoder().decode(s);byte[] oo=new byte[dd.length];for(int i=0;i<dd.length;i++)oo[i]=(byte)(dd[i]^k);return new String(oo,java.nio.charset.StandardCharsets.UTF_8);}\n");
  b.append(" static void ").append(n.mFail).append("(){android.os.Process.killProcess(android.os.Process.myPid());System.exit(1);}\n");
  b.append("}\n");
  return b.toString();
 }
 static String escapeJava(String s){return s.replace("\\","\\\\").replace("\"","\\\"");}
}
