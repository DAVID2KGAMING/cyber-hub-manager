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
 * certificate, looks for root and for an attached debugger, and kills the process if a check fails.
 * No existing class is touched; only AndroidManifest.xml and one new DEX class are added.
 * Scope: only APKs that do not already declare android:application/android:name (no existing
 * custom Application subclass) are supported in this version.
 */
final class ApkProtect {
 private ApkProtect(){}
 static final String GUARD_SIMPLE="ChGuard";

 static JSONObject info(File apk)throws Exception{
  String xml=new Axml().decode(ApkTools.manifestBytes(apk));
  Matcher am=Pattern.compile("<application\\b[^>]*>").matcher(xml);String atag=am.find()?am.group():"";
  String existing=ApkTools.attr(atag,"android:name");
  return new JSONObject().put("package",ApkTools.attr(find(xml),"package")).put("hasCustomApplication",!existing.isEmpty()).put("existingApplication",existing);
 }
 static String find(String xml){Matcher m=Pattern.compile("<manifest\\b[^>]*>").matcher(xml);return m.find()?m.group():"";}

 static JSONObject run(ApkTools.Host e,JSONObject a)throws Exception{
  File src=new File(a.getString("path"));if(!src.getName().toLowerCase(Locale.ROOT).endsWith(".apk"))throw new IOException("Choose an APK file");
  boolean sig=a.optBoolean("signatureCheck",true),root=a.optBoolean("rootCheck",true),dbg=a.optBoolean("debuggerCheck",true);
  if(!sig&&!root&&!dbg)throw new IOException("Choose at least one check");

  Axml ax=new Axml();String xml=ax.decode(ApkTools.manifestBytes(src));
  Matcher rm=Pattern.compile("<manifest\\b[^>]*>").matcher(xml);if(!rm.find())throw new IOException("AndroidManifest.xml has no <manifest> element");
  String pkg=ApkTools.attr(rm.group(),"package");if(pkg.isEmpty())throw new IOException("Cannot read the package name");
  Matcher am=Pattern.compile("<application\\b[^>]*>").matcher(xml);if(!am.find())throw new IOException("AndroidManifest.xml has no <application> element");
  String appTag=am.group(),existingName=ApkTools.attr(appTag,"android:name");
  if(!existingName.isEmpty())throw new IOException("This APK already has a custom Application class ("+existingName+"). Protect APK does not support chaining onto it yet.");

  // Expected signing certificate: whatever ApkTools.publish() will actually sign with.
  byte[] certSha256=sig?e.devSigningCert():null;

  String guardBin=pkg.replace('.', '/')+"/"+GUARD_SIMPLE;
  String javaPkg=pkg;
  String source=guardSource(javaPkg,certSha256,root,dbg);

  File apiJar=e.androidApiJar();
  ClassDef guardClass=compileStandalone("L"+guardBin+";",source,apiJar,e.workspace());

  // Pick the first classes*.dex entry to host the new class (any would do; app loads them all).
  String dexEntry=firstDexEntry(src);
  byte[] dexBytes=FileOps.zipEntry(src,dexEntry,256L*1024*1024);
  File tmpDex=File.createTempFile(".guard-src-",".dex",e.workspace());
  byte[] mergedDex;
  try{
   java.nio.file.Files.write(tmpDex.toPath(),dexBytes);
   DexBackedDexFile original=DexFileFactory.loadDexFile(tmpDex,Opcodes.getDefault());
   if(original.getClasses().stream().anyMatch(c->c.getType().equals(guardClass.getType())))throw new IOException("A class named "+GUARD_SIMPLE+" already exists in this package. Protect APK cannot add its guard.");
   List<ClassDef> all=new ArrayList<>();for(ClassDef c:original.getClasses())all.add(c);all.add(guardClass);
   File out=File.createTempFile(".guard-out-",".dex",e.workspace());
   try{DexPool.writeTo(out.getPath(),new ImmutableDexFile(original.getOpcodes(),all));mergedDex=java.nio.file.Files.readAllBytes(out.toPath());}finally{out.delete();}
  }finally{tmpDex.delete();}

  String newAppTag=appTag.substring(0,appTag.length()-1)+" android:name=\""+ApkTools.escape("."+GUARD_SIMPLE)+"\">";
  String editedXml=xml.substring(0,am.start())+newAppTag+xml.substring(am.end());

  Map<String,byte[]> repl=new HashMap<>();
  repl.put("AndroidManifest.xml",ax.encode(editedXml));
  repl.put(dexEntry,mergedDex);
  JSONObject r=ApkTools.publish(e,src,repl,Collections.<String>emptySet(),"-protected",true);
  return r.put("checks",new JSONObject().put("signature",sig).put("root",root).put("debugger",dbg)).put("class",javaPkg+"."+GUARD_SIMPLE);
 }

 static String firstDexEntry(File apk)throws Exception{
  try(ZipFile z=new ZipFile(apk)){
   if(z.getEntry("classes.dex")!=null)return "classes.dex";
   Enumeration<? extends ZipEntry> en=z.entries();
   while(en.hasMoreElements()){String n=en.nextElement().getName();if(n.matches("classes\\d*\\.dex"))return n;}
  }
  throw new IOException("No DEX found in this APK");
 }

 /** Compile one standalone top-level class with ECJ, convert to DEX with the bundled dx. No project stubs: the guard only uses the public Android API. */
 static ClassDef compileStandalone(String type,String text,File platform,File workspace)throws Exception{
  if(!platform.isFile())throw new IOException("Compiler API library is missing");
  File work=new File(workspace,"guard-"+UUID.randomUUID());if(!work.mkdirs())throw new IOException("Cannot create compiler workspace");
  try{
   String binary=type.substring(1,type.length()-1),simple=binary.substring(binary.lastIndexOf('/')+1);
   File source=new File(work,simple+".java"),output=new File(work,"classes");output.mkdirs();
   FileOps.writeAtomic(source,text.getBytes(StandardCharsets.UTF_8),false);
   StringWriter log=new StringWriter();PrintWriter messages=new PrintWriter(log);
   boolean ok=org.eclipse.jdt.core.compiler.batch.BatchCompiler.compile(new String[]{"-1.8","-proc:none","-g","-nowarn","-encoding","UTF-8","-maxProblems","30","-bootclasspath",platform.getPath(),"-d",output.getPath(),source.getPath()},messages,messages,null);
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
   for(ClassDef c:parsed.getClasses())if(c.getType().equals(type))return ImmutableClassDef.of(c);
   throw new IOException("Compiled class not found: "+type);
  }finally{FileOps.deleteTree(work);}
 }
 static void collectClasses(File dir,List<File> out){File[] fs=dir.listFiles();if(fs==null)return;for(File f:fs)if(f.isDirectory())collectClasses(f,out);else if(f.getName().endsWith(".class"))out.add(f);}

 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}

 static String guardSource(String pkg,byte[] certSha256,boolean root,boolean dbg){
  StringBuilder b=new StringBuilder();
  b.append("package ").append(pkg).append(";\n");
  b.append("import android.app.Application;import android.content.pm.*;import android.content.Context;import java.security.MessageDigest;import java.io.*;\n");
  b.append("public final class ").append(GUARD_SIMPLE).append(" extends Application {\n");
  b.append(" @Override public void onCreate(){super.onCreate();try{check(this);}catch(Throwable t){fail();}}\n");
  b.append(" static void check(Context c)throws Exception{\n");
  if(certSha256!=null){
   b.append("  String expected=\"").append(hex(certSha256)).append("\";\n");
   b.append("  PackageInfo info=c.getPackageManager().getPackageInfo(c.getPackageName(),PackageManager.GET_SIGNATURES);\n");
   b.append("  boolean matched=false;MessageDigest md=MessageDigest.getInstance(\"SHA-256\");\n");
   b.append("  for(Signature s:info.signatures){md.reset();byte[] d=md.digest(s.toByteArray());StringBuilder h=new StringBuilder();for(byte x:d)h.append(String.format(\"%02x\",x&255));if(h.toString().equals(expected))matched=true;}\n");
   b.append("  if(!matched)fail();\n");
  }
  if(root){
   b.append("  String[] paths={\"/system/app/Superuser.apk\",\"/sbin/su\",\"/system/bin/su\",\"/system/xbin/su\",\"/data/local/xbin/su\",\"/data/local/bin/su\",\"/system/sd/xbin/su\",\"/system/bin/failsafe/su\",\"/data/local/su\",\"/su/bin/su\"};\n");
   b.append("  for(String p:paths)if(new File(p).exists())fail();\n");
   b.append("  String tags=android.os.Build.TAGS;if(tags!=null&&tags.contains(\"test-keys\"))fail();\n");
  }
  if(dbg){
   b.append("  if(android.os.Debug.isDebuggerConnected())fail();\n");
   b.append("  try(BufferedReader r=new BufferedReader(new FileReader(\"/proc/self/status\"))){String line;while((line=r.readLine())!=null)if(line.startsWith(\"TracerPid:\")&&!line.trim().endsWith(\"0\"))fail();}catch(Exception ignored){}\n");
  }
  b.append(" }\n");
  b.append(" static void fail(){android.os.Process.killProcess(android.os.Process.myPid());System.exit(1);}\n");
  b.append("}\n");
  return b.toString();
 }
}
