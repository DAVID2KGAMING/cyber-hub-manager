package david.manager;
import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;import java.util.zip.*;
import org.json.*;import com.android.apksig.ApkVerifier;

public final class JavaFlowSmokeTest {
 static int count;static void check(boolean ok,String label){if(!ok)throw new AssertionError(label);count++;System.out.println("PASS "+label);}
 interface Attempt{void run()throws Exception;}
 static String fails(Attempt action)throws Exception{try{action.run();throw new AssertionError("Expected rejection");}catch(IOException expected){return expected.getMessage();}}
 public static void main(String[] args)throws Exception{
  File root=new File(args[0],"java-flow");root.mkdirs();File platform=new File(args[1]),key=new File(args[2]);
  File main=CoreSmokeTest.assemble(root,"classes","Main",42),other=CoreSmokeTest.assemble(root,"classes2","Second",7),apk=new File(root,"editable.apk");
  byte[] manifest=new Axml().encode("<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"demo.fixture\" android:versionCode=\"1\" android:versionName=\"1\"><uses-sdk android:minSdkVersion=\"21\" android:targetSdkVersion=\"28\"/><application android:label=\"Fixture\"/></manifest>");
  try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(apk))){z.putNextEntry(new ZipEntry("AndroidManifest.xml"));z.write(manifest);z.closeEntry();for(File f:Arrays.asList(main,other)){z.putNextEntry(new ZipEntry(f.getName()));z.write(FileOps.read(f,1000000));z.closeEntry();}}
  String original=FileOps.sha256(apk);DexEngine engine=new DexEngine(new File(root,"session"));engine.open(apk,new JSONArray().put("classes.dex").put("classes2.dex"));
  String java=engine.code("Ldemo/Main;","java","auto").getString("text");long started=System.nanoTime();
  engine.saveJava("Ldemo/Main;",java.replace("42","44"),platform);
  check(engine.code("Ldemo/Main;","java","auto").getString("text").contains("44"),"decompiled Java edit compiles into DEX and decompiles with changed value");
  check(FileOps.sha256(apk).equals(original),"Java save leaves original APK untouched until project commit");
  check(Arrays.equals(FileOps.read(other,1000000),FileOps.read(engine.files.get("classes2.dex"),1000000)),"unmodified MultiDex file is byte-identical");
  String source="package demo; public class Main { public static String message(){return \"edited string\";} public static int answer(){return Second.answer()+5;} public static class Nested { public int value(){return 91;} } }";
  engine.saveJava("Ldemo/Main;",source,platform);
  check(engine.classes.containsKey("Ldemo/Main$Nested;"),"Java compilation merges newly generated nested class");
  check(engine.classes.size()==3,"compile-only API and project stubs never leak into output DEX");
  String after=engine.code("Ldemo/Main;","java","auto").getString("text");check(after.contains("edited string")&&after.contains("Second.answer()"),"Java string and cross-DEX method call survive recompile");
  check(engine.code("Ldemo/Main$Nested;","java","auto").getString("class").equals("Ldemo/Main;"),"nested Java editor returns enclosing compilation unit");
  String sessionHash=FileOps.sha256(engine.files.get("classes.dex"));
  String error=fails(()->engine.saveJava("Ldemo/Main;",source.replace("return 91;","return ;"),platform));
  check(error.contains("at line")&&FileOps.sha256(engine.files.get("classes.dex")).equals(sessionHash),"invalid Java reports source line and leaves edited DEX unchanged");
  fails(()->engine.saveJava("Ldemo/Main;",source.replace("package demo;","package renamed;"),platform));
  check(FileOps.sha256(engine.files.get("classes.dex")).equals(sessionHash),"package rename cannot silently delete or replace another class");
  fails(()->engine.saveJava("Ldemo/Main;",source+"\n// Method not decompiled:",platform));
  check(FileOps.sha256(engine.files.get("classes.dex")).equals(sessionHash),"JADX incomplete-method output is not compiled over real bytecode");
  try{engine.commit(new ByteArrayInputStream(new byte[]{1,2,3}));throw new AssertionError("Bad key accepted");}catch(Exception expected){}
  check(FileOps.sha256(apk).equals(original),"failed signing leaves source APK unchanged");
  JSONObject saved;try(InputStream in=new FileInputStream(key)){saved=engine.commit(in);}
  ApkVerifier.Result verified=new ApkVerifier.Builder(apk).build().verify();check(verified.isVerified()&&verified.isVerifiedUsingV1Scheme()&&verified.isVerifiedUsingV2Scheme()&&verified.isVerifiedUsingV3Scheme(),"Save and sign verifies V1, V2 and V3 before publishing");
  check(FileOps.sha256(new File(saved.getString("backup"))).equals(original),"Save and sign keeps exact original backup");
  DexEngine reopened=new DexEngine(new File(root,"reopened"));reopened.open(apk,new JSONArray().put("classes.dex").put("classes2.dex"));check(reopened.code("Ldemo/Main;","java","auto").getString("text").contains("edited string")&&reopened.classes.containsKey("Ldemo/Second;"),"signed APK reopens with Java edits and untouched classes");
  engine.saveJava("Ldemo/Main;",source.replace("edited string","second edit"),platform);try(InputStream in=new FileInputStream(key)){engine.commit(in);}check(new ApkVerifier.Builder(apk).build().verify().isVerified(),"repeat edit/save/sign succeeds in the same project");
  File copy=new File(root,"copy.apk");try(InputStream in=new FileInputStream(key)){ApkSigning.sign(apk,copy,in);}String copyHash=FileOps.sha256(copy);fails(()->{try(InputStream in=new FileInputStream(key)){ApkSigning.sign(apk,copy,in);}});check(FileOps.sha256(copy).equals(copyHash),"signing cannot overwrite an existing output");
  check(Arrays.stream(root.listFiles()).noneMatch(f->f.getName().startsWith(".verified-sign-")||f.getName().startsWith(".dex-commit-")),"signing and commit temporary files are cleaned up");
  File modern=new File(root,"modern.apk");Axml axml=new Axml();String modernXml=axml.decode(manifest).replace("minSdkVersion=\"21\"","minSdkVersion=\"26\"");FileOps.rewriteZip(apk,modern,Collections.singletonMap("AndroidManifest.xml",axml.encode(modernXml)));File modernSigned=new File(root,"modern-signed.apk");try(InputStream in=new FileInputStream(key)){ApkSigning.sign(modern,modernSigned,in);}check(new ApkVerifier.Builder(modernSigned).build().verify().isVerified(),"signing also succeeds for APKs with Android 8+ minimum SDK");
  String androidJava="package demo; public class Main extends android.app.Activity { public void onCreate(android.os.Bundle state){super.onCreate(state); android.widget.Button b=new android.widget.Button(this); b.setText(\"Hello\"); b.setOnClickListener(new android.view.View.OnClickListener(){public void onClick(android.view.View view){android.widget.Toast.makeText(Main.this, \"Changed\", 0).show();}}); setContentView(b);}}";
  engine.saveJava("Ldemo/Main;",androidJava,platform);check(engine.classes.containsKey("Ldemo/Main$1;")&&engine.code("Ldemo/Main;","smali","auto").getString("text").contains("Landroid/app/Activity;"),"Android API calls and anonymous listeners compile into real DEX classes");
  engine.close();reopened.close();System.out.println("ALL "+count+" JAVA/SIGN CHECKS PASSED in "+((System.nanoTime()-started)/1000000)+" ms (JVM, not Android runtime)");
 }
}
