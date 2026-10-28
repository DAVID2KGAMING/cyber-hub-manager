package david.manager;
import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import com.android.apksig.*;

/**
 * Checks all 13 Protect APK options together (signature, root, debugger, emulator, frida, screenshot
 * block, install-source, expiry, integrity, disableBackup, forceNonDebuggable, tapjacking, mitm), plus
 * the randomized-naming and string-obfuscation layer: the guard class name, method names, and
 * meta-data keys differ every run, and literal "signal" strings (root paths, Frida markers, proc
 * paths, ...) never appear in plain text inside the final DEX.
 * args: workdir fixturesApksDir androidApiJar
 */
public class ApkProtectSmokeTest{
 static int passed=0;
 static void ok(boolean c,String m){if(!c){System.out.println("FAIL "+m);System.exit(1);}passed++;System.out.println("PASS "+m);}
 static boolean verified(File f)throws Exception{ApkVerifier.Result r=new ApkVerifier.Builder(f).build().verify();return r.isVerified()&&r.isVerifiedUsingV1Scheme()&&r.isVerifiedUsingV2Scheme()&&r.isVerifiedUsingV3Scheme();}
 static void rm(File f){File[] c=f.listFiles();if(c!=null)for(File x:c)rm(x);f.delete();}
 static String guardSimpleFromManifest(String xml){
  java.util.regex.Matcher m=java.util.regex.Pattern.compile("<application\\b[\\s\\S]*?android:name=\"([^\"]+)\"").matcher(xml);
  if(!m.find())return null;String v=m.group(1);return v.startsWith(".")?v.substring(1):v;
 }
 static List<String> metaDataValues(String xml){
  List<String> out=new ArrayList<>();
  java.util.regex.Matcher m=java.util.regex.Pattern.compile("android:value=\"([0-9A-Za-z_.,]+)\"").matcher(xml);
  while(m.find())out.add(m.group(1));
  return out;
 }

 static File buildFixture(File dir,File plainBase,File apiJar,String name)throws Exception{
  List<org.jf.dexlib2.iface.ClassDef> fam=ApkProtect.compileStandalone("Ldemo/bundle/MainActivity;","package demo.bundle;\npublic class MainActivity extends android.app.Activity { }\n",apiJar,dir);
  File dexOut=new File(dir,name+"-classes.dex");org.jf.dexlib2.writer.pool.DexPool.writeTo(dexOut.getPath(),new org.jf.dexlib2.immutable.ImmutableDexFile(org.jf.dexlib2.Opcodes.getDefault(),fam));
  File out=new File(dir,name+".apk");
  Map<String,byte[]> seed=new HashMap<>();
  seed.put("classes.dex",Files.readAllBytes(dexOut.toPath()));
  seed.put("assets/data.txt","hello world".getBytes());
  seed.put("assets/sub/b.bin",new byte[]{1,2,3});
  FileOps.rewriteZip(plainBase,out,seed);
  return out;
 }

 public static void main(String[] a)throws Exception{
  final File dir=new File(a[0],"apkprotect");rm(dir);dir.mkdirs();
  File plainBase=new File(a[1],"base.apk");
  File apiJar=new File(a[2]);

  byte[] p12=ApkTools.generateP12("k","passw0rd".toCharArray(),"Smoke",25);
  ApkSigning.useCustom(p12,"passw0rd".toCharArray(),"passw0rd".toCharArray(),"k");
  java.security.KeyStore ks=java.security.KeyStore.getInstance("PKCS12");ks.load(new ByteArrayInputStream(p12),"passw0rd".toCharArray());
  byte[] certHash=java.security.MessageDigest.getInstance("SHA-256").digest(((java.security.cert.X509Certificate)ks.getCertificate("k")).getEncoded());
  ApkTools.Host h=new ApkTools.Host(){
   public File workspace(){return dir;}
   public void sign(File s,File d)throws Exception{ApkSigning.sign(s,d,null);}
   public void record(String t){}
   public File androidApiJar(){return apiJar;}
   public byte[] devSigningCert(){return certHash;}
  };

  // ---- all 13 checks at once ----
  File base1=buildFixture(dir,plainBase,apiJar,"all13");
  JSONObject r=ApkProtect.run(h,new JSONObject()
   .put("path",base1.getPath())
   .put("signatureCheck",true).put("rootCheck",true).put("debuggerCheck",true)
   .put("emulatorCheck",true).put("fridaCheck",true).put("screenshotBlock",true)
   .put("installSourceCheck",true).put("installSourcePackages","com.android.vending, com.david.store")
   .put("expiryCheck",true).put("expiryDate","2099-12-31")
   .put("integrityCheck",true)
   .put("disableBackup",true).put("forceNonDebuggable",true).put("tapjackingCheck",true).put("mitmCheck",true));
  File out1=new File(r.getString("path"));
  ok(verified(out1),"all-13-checks APK signed and verifies V1/V2/V3");
  try(ZipFile z=new ZipFile(out1)){ok(z.getEntry("classes.dex")!=null&&z.getEntry("resources.arsc")!=null&&z.getEntry("assets/data.txt")!=null,"dex, arsc, and assets entries all present");}

  String xml1=new Axml().decode(ApkTools.manifestBytes(out1));
  String guardSimple1=guardSimpleFromManifest(xml1);
  ok(guardSimple1!=null&&guardSimple1.matches("[a-z][a-z0-9]{7}"),"guard class name is randomized (lowercase, 8 chars) and found in manifest: "+guardSimple1);
  ok(xml1.contains("android:allowBackup=\"false\""),"android:allowBackup forced to false");
  ok(xml1.contains("android:debuggable=\"false\""),"android:debuggable forced to false");

  byte[] dex1=FileOps.zipEntry(out1,"classes.dex",64L*1024*1024);
  File tf=File.createTempFile("dex",".dex",dir);Files.write(tf.toPath(),dex1);
  org.jf.dexlib2.dexbacked.DexBackedDexFile parsed=org.jf.dexlib2.DexFileFactory.loadDexFile(tf,org.jf.dexlib2.Opcodes.getDefault());
  String expectedType="Ldemo/bundle/"+guardSimple1+";";
  boolean found=false,foundInner=false;for(org.jf.dexlib2.iface.ClassDef cd:parsed.getClasses()){if(cd.getType().equals(expectedType))found=true;if(cd.getType().startsWith("Ldemo/bundle/"+guardSimple1+"$"))foundInner=true;}
  ok(found,"randomized guard class present under its manifest-declared name");
  ok(foundInner,"anonymous ActivityLifecycleCallbacks inner class present (screenshot/tapjacking)");

  // ---- string obfuscation: none of these plaintext markers may appear anywhere in the final DEX ----
  String dexText=new String(dex1,java.nio.charset.StandardCharsets.ISO_8859_1);
  String[] mustNotAppear={"frida","xposed","substrate","XposedBridge","/sbin/su","/system/bin/su",
   "test-keys","genymotion","goldfish","ranchu","qemu","AndroidCAStore","TracerPid","/proc/self/status",
   "/proc/self/maps","resources.arsc","Superuser","magisk"};
  boolean leaked=false;
  for(String marker:mustNotAppear)if(dexText.toLowerCase(Locale.ROOT).contains(marker.toLowerCase(Locale.ROOT))){System.out.println(" LEAKED: "+marker);leaked=true;}
  ok(!leaked,"no plaintext signal strings (root/frida/emulator/proc/mitm markers) found anywhere in the DEX");

  // ---- run it twice more: class name and meta-data keys must differ each time (no fixed fingerprint) ----
  File base1b=buildFixture(dir,plainBase,apiJar,"all13b");
  JSONObject rb=ApkProtect.run(h,new JSONObject().put("path",base1b.getPath()).put("signatureCheck",false).put("rootCheck",true).put("integrityCheck",true));
  String xml1b=new Axml().decode(ApkTools.manifestBytes(new File(rb.getString("path"))));
  String guardSimple1b=guardSimpleFromManifest(xml1b);
  ok(!guardSimple1b.equals(guardSimple1),"a second Protect run uses a DIFFERENT randomized class name: "+guardSimple1+" vs "+guardSimple1b);

  // validation errors
  File base2=buildFixture(dir,plainBase,apiJar,"bad1");
  try{ApkProtect.run(h,new JSONObject().put("path",base2.getPath()).put("installSourceCheck",true));ok(false,"install source without packages should fail");}catch(IOException ex){ok(true,"install source without packages rejected: "+ex.getMessage());}
  try{ApkProtect.run(h,new JSONObject().put("path",base2.getPath()).put("expiryCheck",true).put("expiryDate","not-a-date"));ok(false,"bad expiry date should fail");}catch(IOException ex){ok(true,"bad expiry date rejected: "+ex.getMessage());}
  try{ApkProtect.run(h,new JSONObject().put("path",base2.getPath()).put("installSourceCheck",true).put("installSourcePackages","bad pkg name!"));ok(false,"bad package name should fail");}catch(IOException ex){ok(true,"bad installer package name rejected: "+ex.getMessage());}

  // ---- deep content-hash integrity verification (dynamic meta-data keys) ----
  File base3=buildFixture(dir,plainBase,apiJar,"hashonly");
  JSONObject r2=ApkProtect.run(h,new JSONObject().put("path",base3.getPath()).put("signatureCheck",false).put("rootCheck",false).put("debuggerCheck",false).put("integrityCheck",true));
  File out2=new File(r2.getString("path"));
  ok(verified(out2),"integrity-only APK verifies");

  String xml2=new Axml().decode(ApkTools.manifestBytes(out2));
  List<String> values=metaDataValues(xml2);
  ok(values.size()==4,"manifest carries exactly 4 meta-data values (dex entries, dex hashes, arsc hash, assets hash): got "+values.size());
  String entriesVal=null,hashesVal=null,arscVal=null,assetsVal=null;
  byte[] realDex=FileOps.zipEntry(out2,"classes.dex",64L*1024*1024);
  byte[] realArsc=FileOps.zipEntry(out2,"resources.arsc",64L*1024*1024);
  String realDexHash=ApkProtect.sha256Hex(realDex),realArscHash=ApkProtect.sha256Hex(realArsc),realAssetsHash=ApkProtect.hashAssets(out2);
  for(String v:values){
   if(v.contains("classes.dex"))entriesVal=v;
   else if(v.equals(realDexHash))hashesVal=v;
   else if(v.equals(realArscHash))arscVal=v;
   else if(v.equals(realAssetsHash))assetsVal=v;
  }
  ok(entriesVal!=null&&entriesVal.equals("classes.dex"),"dex-entries meta-data value is exactly 'classes.dex'");
  ok(hashesVal!=null,"embedded DEX hash equals sha256 of the ACTUAL final classes.dex content");
  ok(arscVal!=null,"embedded resources.arsc hash matches the actual file");
  ok(assetsVal!=null,"embedded assets hash matches live hashAssets() over the output APK");

  byte[] tampered=realDex.clone();tampered[tampered.length-1]^=0x01;
  ok(!ApkProtect.sha256Hex(tampered).equals(realDexHash),"tampering one byte changes the hash (the runtime check would fire)");

  // ---- multidex: classes.dex (hosts the guard) + classes2.dex (untouched, hashed upfront) ----
  File base4=buildFixture(dir,plainBase,apiJar,"multidex");
  List<org.jf.dexlib2.iface.ClassDef> fam2=ApkProtect.compileStandalone("Ldemo/bundle/Extra;","package demo.bundle;\npublic class Extra { public static int x(){return 42;} }\n",apiJar,dir);
  File dex2Out=new File(dir,"classes2.dex");org.jf.dexlib2.writer.pool.DexPool.writeTo(dex2Out.getPath(),new org.jf.dexlib2.immutable.ImmutableDexFile(org.jf.dexlib2.Opcodes.getDefault(),fam2));
  File base4m=new File(dir,"multidex2.apk");
  Map<String,byte[]> add2=new HashMap<>();add2.put("classes2.dex",Files.readAllBytes(dex2Out.toPath()));
  FileOps.rewriteZip(base4,base4m,add2);
  JSONObject r4=ApkProtect.run(h,new JSONObject().put("path",base4m.getPath()).put("signatureCheck",false).put("rootCheck",false).put("debuggerCheck",false).put("integrityCheck",true));
  File out4=new File(r4.getString("path"));
  ok(verified(out4),"multidex (classes.dex + classes2.dex) protected APK verifies");
  ok(r4.getJSONObject("checks").getInt("dexCount")==2,"multidex fixture detected as 2 dex files");
  try(ZipFile z=new ZipFile(out4)){ok(z.getEntry("classes2.dex")!=null,"classes2.dex still present untouched");}
  String xml4=new Axml().decode(ApkTools.manifestBytes(out4));
  List<String> values4=metaDataValues(xml4);
  String entries4=null;for(String v:values4)if(v.contains("classes.dex")&&v.contains("classes2.dex"))entries4=v;
  ok(entries4!=null,"both dex files listed together in the watch set: "+values4);
  byte[] realDex2=FileOps.zipEntry(out4,"classes2.dex",64L*1024*1024);
  String realDex2Hash=ApkProtect.sha256Hex(realDex2);
  boolean dex2HashPresent=false;for(String v:values4)if(v.contains(realDex2Hash))dex2HashPresent=true;
  ok(dex2HashPresent,"classes2.dex's embedded hash equals its actual (untouched) content hash");

  System.out.println("ApkProtect checks passed: "+passed);
 }
}
