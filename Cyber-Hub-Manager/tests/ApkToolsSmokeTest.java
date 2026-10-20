package david.manager;
import org.json.*;import java.io.*;import java.nio.file.*;import java.util.*;import java.util.zip.*;import java.security.*;import com.android.apksig.*;
/** Checks for ApkTools: manifest/clone/permissions, entries, hex, ARSC strings, project build, generated signing key. args: workdir fixturesApksDir */
public class ApkToolsSmokeTest{
 static int passed=0;
 static void ok(boolean c,String m){if(!c){System.out.println("FAIL "+m);System.exit(1);}passed++;System.out.println("PASS "+m);}
 static boolean verified(File f)throws Exception{ApkVerifier.Result r=new ApkVerifier.Builder(f).build().verify();return r.isVerified()&&r.isVerifiedUsingV1Scheme()&&r.isVerifiedUsingV2Scheme()&&r.isVerifiedUsingV3Scheme();}
 static void rm(File f){File[] c=f.listFiles();if(c!=null)for(File x:c)rm(x);f.delete();}
 public static void main(String[] a)throws Exception{
  final File dir=new File(a[0],"apktools");rm(dir);dir.mkdirs();File fixture=new File(a[1],"base.apk");
  final File base=new File(dir,"base.apk");Files.copy(fixture.toPath(),base.toPath());
  byte[] p12=ApkTools.generateP12("k","passw0rd".toCharArray(),"Smoke",25);
  KeyStore ks=KeyStore.getInstance("PKCS12");ks.load(new ByteArrayInputStream(p12),"passw0rd".toCharArray());
  java.security.cert.X509Certificate cert=(java.security.cert.X509Certificate)ks.getCertificate("k");cert.verify(cert.getPublicKey());ok(cert.getSubjectX500Principal().getName().contains("Smoke"),"generated certificate is self-consistent");
  ApkSigning.useCustom(p12,"passw0rd".toCharArray(),"passw0rd".toCharArray(),"k");
  ApkTools.Host h=new ApkTools.Host(){public File workspace(){return dir;}public void sign(File s,File d)throws Exception{ApkSigning.sign(s,d,null);}public void record(String t){}};
  // manifest clone
  ok(ApkTools.manifestInfo(base).getString("package").equals("demo.bundle"),"manifestInfo");
  JSONObject cl=ApkTools.manifestApply(h,new JSONObject().put("path",base.getPath()).put("package","david.manager").put("versionName","9.9").put("versionCode","42").put("label","My Clone"),true);
  ok(verified(new File(cl.getString("path"))),"clone signed with generated key verifies V1/V2/V3");
  JSONObject ci=ApkTools.manifestInfo(new File(cl.getString("path")));ok(ci.getString("package").equals("david.manager")&&ci.getString("versionName").equals("9.9")&&ci.getString("versionCode").equals("42")&&ci.getString("label").equals("My Clone"),"clone manifest values");
 // 1. rich manifest text edit
  String xml="<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n    android:versionCode=\"1\"\n    android:versionName=\"1.0\"\n    android:sharedUserId=\"my.shared\"\n    package=\"com.old.app\">\n    <uses-permission\n        android:name=\"android.permission.INTERNET\">\n    </uses-permission>\n    <uses-permission android:name=\"com.google.android.gms.permission.AD_ID\"/>\n    <uses-permission android:name=\"com.old.app.permission.PUSH\"/>\n    <permission android:name=\"com.old.app.permission.PUSH\"/>\n    <application android:name=\".App\" android:label=\"Old\">\n        <activity android:name=\".ui.Main\"/>\n        <activity android:name=\"Plain\"/>\n        <activity android:name=\"com.other.Lib\"/>\n        <provider android:name=\"androidx.core.content.FileProvider\" android:authorities=\"com.old.app.fileprovider\"/>\n    </application>\n</manifest>\n";
  String ed=ApkTools.editManifest(xml,new JSONObject().put("package","david.manager").put("removePermissions",new JSONArray().put("com.google.android.gms.permission.AD_ID")),true);
  ok(ed.contains("package=\"david.manager\""),"package renamed");
  ok(ed.contains("android:name=\"com.old.app.App\"")&&ed.contains("android:name=\"com.old.app.ui.Main\"")&&ed.contains("android:name=\"com.old.app.Plain\"")&&ed.contains("android:name=\"com.other.Lib\""),"class names pinned to old package");
  ok(ed.contains("android:authorities=\"david.manager.fileprovider\""),"authority moved");
  ok(ed.contains("<permission android:name=\"david.manager.permission.PUSH\"")&&ed.contains("<uses-permission android:name=\"david.manager.permission.PUSH\""),"custom permission moved");
  ok(!ed.contains("AD_ID")&&ed.contains("android.permission.INTERNET"),"AD_ID removed, INTERNET kept");
  ok(!ed.contains("sharedUserId"),"sharedUserId dropped for clone");
  String ed2=ApkTools.editManifest(xml,new JSONObject().put("removeAllPermissions",true),false);
  ok(!ed2.contains("uses-permission")&&ed2.contains("<permission"),"remove all uses-permission");
  // 2. replace entry / delete entry (host)
  File png=new File(dir,"x.png");Files.write(png.toPath(),new byte[]{(byte)0x89,'P','N','G',13,10,26,10,0,0});
  JSONObject r=ApkTools.replaceEntry(h,new JSONObject().put("archive",base.getPath()).put("entry","res/drawable/icon.png").put("source",png.getPath()).put("add",true));
  ok(verified(new File(r.getString("path"))),"added PNG entry, APK re-signed and verified");
  try(ZipFile z=new ZipFile(r.getString("path"))){ok(z.getEntry("res/drawable/icon.png")!=null&&z.getEntry("resources.arsc")!=null,"entry present, arsc kept");}
  try{ApkTools.replaceEntry(h,new JSONObject().put("archive",base.getPath()).put("entry","res/a.png").put("source",base.getPath()).put("add",true));ok(false,"fake png rejected");}catch(IOException ex){ok(true,"non-PNG rejected for .png entry");}
  JSONObject r2=ApkTools.deleteEntries(h,new JSONObject().put("archive",r.getString("path")).put("entries",new JSONArray().put("res/drawable/icon.png")));
  try(ZipFile z=new ZipFile(r2.getString("path"))){ok(z.getEntry("res/drawable/icon.png")==null&&verified(new File(r2.getString("path"))),"delete entry, verified");}
  
 // hex patch in archive entry + plain file
  JSONObject hp=ApkTools.hexPatch(h,new JSONObject().put("archive",base.getPath()).put("entry","resources.arsc").put("patches",new JSONArray().put(new JSONObject().put("offset",100).put("hex","41 42"))));
  ok(verified(new File(hp.getString("path"))),"archive hex patch re-signed");
  byte[] pe=FileOps.zipEntry(new File(hp.getString("path")),"resources.arsc",1<<20);ok(pe[100]==0x41&&pe[101]==0x42,"patched bytes in entry");
  File plain=new File(dir,"f.bin");Files.write(plain.toPath(),new byte[]{1,2,3,4});
  JSONObject pp=ApkTools.hexPatch(h,new JSONObject().put("path",plain.getPath()).put("patches",new JSONArray().put(new JSONObject().put("offset",1).put("hex","FF"))));
  ok(Files.readAllBytes(plain.toPath())[1]==(byte)0xFF&&new File(pp.getString("backup")).isFile(),"plain file patched with .bak");
  JSONObject hf=ApkTools.hexFind(h,new JSONObject().put("path",plain.getPath()).put("pattern","FF 03"));ok(hf.getJSONArray("hits").length()==1,"hex find");
  // ARSC strings
  JSONObject st=ApkTools.arscStrings(new JSONObject().put("path",base.getPath()));System.out.println(" "+st);
  JSONArray items=st.getJSONArray("items");ok(items.length()>0,"arsc strings listed");
  int idx=items.getJSONObject(0).getInt("index");String old=items.getJSONObject(0).getString("text");
  JSONObject ar=ApkTools.arscReplace(h,new JSONObject().put("path",base.getPath()).put("changes",new JSONArray().put(new JSONObject().put("index",idx).put("text",old+" EDITED"))));
  File arf=new File(ar.getString("path"));ok(verified(arf),"arsc edit re-signed and verified");
  JSONObject st2=ApkTools.arscStrings(new JSONObject().put("path",arf.getPath()));ok(st2.toString().contains(old+" EDITED"),"edited string reads back");
  // project decode -> edit manifest text -> build
  JSONObject pd=ApkTools.projectDecode(new JSONObject().put("path",base.getPath()).put("destination",dir.getPath()).put("name","proj"));
  File mf=new File(dir,"proj/AndroidManifest.xml");String t=new String(Files.readAllBytes(mf.toPath()),"UTF-8");
  try{ApkTools.projectBuild(h,new JSONObject().put("folder",new File(dir,"proj").getPath()));ok(false,"unchanged project rejected");}catch(IOException ex){ok(true,"unchanged project rejected: "+ex.getMessage());}
  Files.write(mf.toPath(),t.replace("android:versionName=\"1.0\"","android:versionName=\"2.5\"").getBytes("UTF-8"));
  Files.write(new File(dir,"proj/assets-note.txt").toPath(),"hello".getBytes());
  JSONObject pb=ApkTools.projectBuild(h,new JSONObject().put("folder",new File(dir,"proj").getPath()).put("name","rebuilt"));System.out.println(" "+pb);
  File built=new File(pb.getString("path"));ok(verified(built),"project build signed + verified");
  ok(ApkTools.manifestInfo(built).getString("versionName").equals("2.5"),"edited XML re-encoded");
  try(ZipFile z=new ZipFile(built)){ok(z.getEntry("assets-note.txt")!=null,"new file added");}
  // delete a file from project -> removed
  Files.delete(new File(dir,"proj/resources.arsc").toPath());
  JSONObject pb2=ApkTools.projectBuild(h,new JSONObject().put("folder",new File(dir,"proj").getPath()).put("name","rebuilt2"));
  try(ZipFile z=new ZipFile(pb2.getString("path"))){ok(z.getEntry("resources.arsc")==null,"deleted file removed from APK");}
 
 System.out.println("ApkTools checks passed: "+passed);
}}
