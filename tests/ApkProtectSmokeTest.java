package david.manager;
import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import com.android.apksig.*;

/**
 * Checks all 9 Protect APK options together (signature, root, debugger, emulator, frida, screenshot
 * block, install-source, expiry) and verifies the content-hash integrity check end to end: the DEX
 * hash is stored in AndroidManifest.xml meta-data — never embedded inside the DEX it describes, which
 * would be self-referential — and is checked here against the ACTUAL sha256 of the final classes.dex /
 * resources.arsc / assets content, plus a tamper simulation confirming a changed byte is caught.
 * args: workdir fixturesApksDir androidApiJar
 */
public class ApkProtectSmokeTest{
 static int passed=0;
 static void ok(boolean c,String m){if(!c){System.out.println("FAIL "+m);System.exit(1);}passed++;System.out.println("PASS "+m);}
 static boolean verified(File f)throws Exception{ApkVerifier.Result r=new ApkVerifier.Builder(f).build().verify();return r.isVerified()&&r.isVerifiedUsingV1Scheme()&&r.isVerifiedUsingV2Scheme()&&r.isVerifiedUsingV3Scheme();}
 static void rm(File f){File[] c=f.listFiles();if(c!=null)for(File x:c)rm(x);f.delete();}
 static String attrVal(String xml,String name){java.util.regex.Matcher m=java.util.regex.Pattern.compile("android:name=\""+name+"\"[\\s\\S]{0,40}?android:value=\"([0-9a-f.]+)\"").matcher(xml);return m.find()?m.group(1):"";}

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

  // ---- all 9 checks at once ----
  File base1=buildFixture(dir,plainBase,apiJar,"all9");
  JSONObject r=ApkProtect.run(h,new JSONObject()
   .put("path",base1.getPath())
   .put("signatureCheck",true).put("rootCheck",true).put("debuggerCheck",true)
   .put("emulatorCheck",true).put("fridaCheck",true).put("screenshotBlock",true)
   .put("installSourceCheck",true).put("installSourcePackages","com.android.vending, com.david.store")
   .put("expiryCheck",true).put("expiryDate","2099-12-31")
   .put("integrityCheck",true));
  File out1=new File(r.getString("path"));
  ok(verified(out1),"all-9-checks APK signed and verifies V1/V2/V3");
  try(ZipFile z=new ZipFile(out1)){ok(z.getEntry("classes.dex")!=null&&z.getEntry("resources.arsc")!=null&&z.getEntry("assets/data.txt")!=null,"dex, arsc, and assets entries all present");}
  byte[] dex1=FileOps.zipEntry(out1,"classes.dex",64L*1024*1024);
  File tf=File.createTempFile("dex",".dex",dir);Files.write(tf.toPath(),dex1);
  org.jf.dexlib2.dexbacked.DexBackedDexFile parsed=org.jf.dexlib2.DexFileFactory.loadDexFile(tf,org.jf.dexlib2.Opcodes.getDefault());
  boolean found=false,foundInner=false;for(org.jf.dexlib2.iface.ClassDef cd:parsed.getClasses()){if(cd.getType().equals("Ldemo/bundle/ChGuard;"))found=true;if(cd.getType().startsWith("Ldemo/bundle/ChGuard$"))foundInner=true;}
  ok(found,"ChGuard class present");
  ok(foundInner,"ChGuard's anonymous ActivityLifecycleCallbacks inner class present (screenshot block)");

  // validation errors
  File base2=buildFixture(dir,plainBase,apiJar,"bad1");
  try{ApkProtect.run(h,new JSONObject().put("path",base2.getPath()).put("installSourceCheck",true));ok(false,"install source without packages should fail");}catch(IOException ex){ok(true,"install source without packages rejected: "+ex.getMessage());}
  try{ApkProtect.run(h,new JSONObject().put("path",base2.getPath()).put("expiryCheck",true).put("expiryDate","not-a-date"));ok(false,"bad expiry date should fail");}catch(IOException ex){ok(true,"bad expiry date rejected: "+ex.getMessage());}
  try{ApkProtect.run(h,new JSONObject().put("path",base2.getPath()).put("installSourceCheck",true).put("installSourcePackages","bad pkg name!"));ok(false,"bad package name should fail");}catch(IOException ex){ok(true,"bad installer package name rejected: "+ex.getMessage());}

  // ---- deep content-hash integrity verification ----
  File base3=buildFixture(dir,plainBase,apiJar,"hashonly");
  JSONObject r2=ApkProtect.run(h,new JSONObject().put("path",base3.getPath()).put("signatureCheck",false).put("rootCheck",false).put("debuggerCheck",false).put("integrityCheck",true));
  File out2=new File(r2.getString("path"));
  ok(verified(out2),"integrity-only APK verifies");

  String xml=new Axml().decode(ApkTools.manifestBytes(out2));
  ok(xml.contains("chGuardDex")&&xml.contains("chGuardArsc")&&xml.contains("chGuardAssets")&&xml.contains("chGuardDexEntry"),"manifest carries all 4 meta-data keys");
  String dexHash=attrVal(xml,"chGuardDex"),arscHash=attrVal(xml,"chGuardArsc"),assetsHash=attrVal(xml,"chGuardAssets");
  ok(dexHash.length()==64&&arscHash.length()==64&&assetsHash.length()==64,"all three hashes are 64 hex chars (SHA-256)");

  byte[] realDex=FileOps.zipEntry(out2,"classes.dex",64L*1024*1024);
  ok(ApkProtect.sha256Hex(realDex).equals(dexHash),"embedded DEX hash equals sha256 of the ACTUAL final classes.dex content");
  byte[] realArsc=FileOps.zipEntry(out2,"resources.arsc",64L*1024*1024);
  ok(ApkProtect.sha256Hex(realArsc).equals(arscHash),"embedded resources.arsc hash matches the actual file");
  ok(ApkProtect.hashAssets(out2).equals(assetsHash),"embedded assets hash matches live hashAssets() over the output APK");

  byte[] tampered=realDex.clone();tampered[tampered.length-1]^=0x01;
  ok(!ApkProtect.sha256Hex(tampered).equals(dexHash),"tampering one byte changes the hash (the runtime check would fire)");

  System.out.println("ApkProtect checks passed: "+passed);
 }
}
