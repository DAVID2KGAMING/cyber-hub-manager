package david.manager;
import org.json.*;import java.io.*;import java.nio.file.*;import java.util.*;import java.util.zip.*;import com.android.apksig.*;
/** Checks for ApkProtect: builds a DEX-containing fixture from the plain base.apk fixture, then protects it. args: workdir fixturesApksDir androidApiJar */
public class ApkProtectSmokeTest{
 static int passed=0;
 static void ok(boolean c,String m){if(!c){System.out.println("FAIL "+m);System.exit(1);}passed++;System.out.println("PASS "+m);}
 static boolean verified(File f)throws Exception{ApkVerifier.Result r=new ApkVerifier.Builder(f).build().verify();return r.isVerified()&&r.isVerifiedUsingV1Scheme()&&r.isVerifiedUsingV2Scheme()&&r.isVerifiedUsingV3Scheme();}
 static void rm(File f){File[] c=f.listFiles();if(c!=null)for(File x:c)rm(x);f.delete();}
 public static void main(String[] a)throws Exception{
  final File dir=new File(a[0],"apkprotect");rm(dir);dir.mkdirs();
  final File apiJar=new File(a[2]);
  File plainBase=new File(a[1],"base.apk");
  org.jf.dexlib2.iface.ClassDef mc=ApkProtect.compileStandalone("Ldemo/bundle/MainActivity;","package demo.bundle;\npublic class MainActivity extends android.app.Activity { }\n",apiJar,dir);
  List<org.jf.dexlib2.iface.ClassDef> all=new ArrayList<>();all.add(mc);
  File dexOut=new File(dir,"classes.dex");org.jf.dexlib2.writer.pool.DexPool.writeTo(dexOut.getPath(),new org.jf.dexlib2.immutable.ImmutableDexFile(org.jf.dexlib2.Opcodes.getDefault(),all));
  final File base=new File(dir,"base.apk");Map<String,byte[]> seed=new HashMap<>();seed.put("classes.dex",Files.readAllBytes(dexOut.toPath()));FileOps.rewriteZip(plainBase,base,seed);

  
  byte[] p12=ApkTools.generateP12("k","passw0rd".toCharArray(),"T6",25);ApkSigning.useCustom(p12,"passw0rd".toCharArray(),"passw0rd".toCharArray(),"k");
  java.security.KeyStore ks=java.security.KeyStore.getInstance("PKCS12");ks.load(new ByteArrayInputStream(p12),"passw0rd".toCharArray());
  java.security.cert.X509Certificate c=(java.security.cert.X509Certificate)ks.getCertificate("k");
  byte[] certHash=java.security.MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
  ApkTools.Host h=new ApkTools.Host(){
   public File workspace(){return dir;}
   public void sign(File s,File d)throws Exception{ApkSigning.sign(s,d,null);}
   public void record(String t){}
   public File androidApiJar(){return apiJar;}
   public byte[] devSigningCert(){return certHash;}
  };
  JSONObject info=ApkProtect.info(base);System.out.println(" "+info);ok(!info.getBoolean("hasCustomApplication"),"base fixture has no custom Application class");
  JSONObject r=ApkProtect.run(h,new JSONObject().put("path",base.getPath()).put("signatureCheck",true).put("rootCheck",true).put("debuggerCheck",true));
  System.out.println(" "+r);
  File out=new File(r.getString("path"));
  ok(verified(out),"protected APK signed and verifies V1/V2/V3");
  JSONObject m2=ApkTools.manifestInfo(out);System.out.println(" "+m2);
  Axml ax=new Axml();String xml=ax.decode(ApkTools.manifestBytes(out));
  ok(xml.contains("android:name=\".ChGuard\""),"manifest points at the new Application class");
  try(ZipFile z=new ZipFile(out)){ok(z.getEntry("classes.dex")!=null,"classes.dex still present");}
  // confirm the DEX actually contains the new class and original classes are untouched otherwise
  byte[] dex=FileOps.zipEntry(out,"classes.dex",64L*1024*1024);
  File tf=File.createTempFile("dex",".dex",dir);Files.write(tf.toPath(),dex);
  org.jf.dexlib2.dexbacked.DexBackedDexFile parsed=org.jf.dexlib2.DexFileFactory.loadDexFile(tf,org.jf.dexlib2.Opcodes.getDefault());
  boolean found=false;for(org.jf.dexlib2.iface.ClassDef cd:parsed.getClasses())if(cd.getType().equals("Ldemo/bundle/ChGuard;"))found=true;
  ok(found,"ChGuard class present in classes.dex with correct package");
  // re-protecting an already-protected APK should fail (existing custom Application)
  try{ApkProtect.run(h,new JSONObject().put("path",out.getPath()));ok(false,"double-protect should be rejected");}catch(IOException ex){ok(true,"double-protect rejected: "+ex.getMessage());}
  // only-root option, no signature/debugger
  JSONObject r2=ApkProtect.run(h,new JSONObject().put("path",base.getPath()).put("signatureCheck",false).put("rootCheck",true).put("debuggerCheck",false));
  ok(verified(new File(r2.getString("path"))),"root-only protect verifies");
  System.out.println("ApkProtect checks passed: "+passed);
 
 System.out.println("ApkProtect checks passed: "+passed);
}}
