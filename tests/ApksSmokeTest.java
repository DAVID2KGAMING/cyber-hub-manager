package david.manager;
import java.io.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.util.*;import java.util.zip.*;
import org.json.*;import com.android.apksig.ApkVerifier;import com.google.protobuf.CodedOutputStream;

public final class ApksSmokeTest {
 static int checks;static File root,key,cache;
 static void check(boolean b,String message){if(!b)throw new AssertionError(message);checks++;System.out.println("PASS "+message);}
 interface Attempt{void run()throws Exception;}
 static String reject(Attempt a)throws Exception{try{a.run();throw new AssertionError("Expected rejection");}catch(IOException ex){return ex.getMessage();}}
 static byte[] utf(String s){return s.getBytes(StandardCharsets.UTF_8);}
 static File zip(String name,Map<String,byte[]> items)throws Exception{File f=new File(root,name);try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(f))){for(Map.Entry<String,byte[]> e:items.entrySet()){z.putNextEntry(new ZipEntry(e.getKey()));z.write(e.getValue());z.closeEntry();}}return f;}
 static Map<String,byte[]> items(Object... values){Map<String,byte[]> m=new LinkedHashMap<>();for(int i=0;i<values.length;i+=2)m.put((String)values[i],(byte[])values[i+1]);return m;}
 static byte[] bytes(File f)throws IOException{return FileOps.read(f,ApksConverter.MAX_APK);}
 static File set(String name,File... files)throws Exception{Map<String,byte[]> m=new LinkedHashMap<>();for(int i=0;i<files.length;i++)m.put("nested/"+i+"/"+files[i].getName(),bytes(files[i]));return zip(name,m);}
 static JSONObject convert(File source,String name,String id)throws Exception{JSONObject info=ApksConverter.inspect(source);try(InputStream in=new FileInputStream(key)){return ApksConverter.convert(source,new File(root,name),id==null?info.getJSONArray("choices").getJSONObject(0).getString("id"):id,info.getString("fingerprint"),cache,in,null);}}
 static String manifest(File file)throws Exception{return new Axml().decode(FileOps.zipEntry(file,"AndroidManifest.xml",8000000));}
 static File changedManifest(File src,String name,java.util.function.UnaryOperator<String> change)throws Exception{byte[] data=FileOps.zipEntry(src,"AndroidManifest.xml",8000000);Axml a=new Axml();String xml=a.decode(data);File out=new File(root,name);FileOps.rewriteZip(src,out,Collections.singletonMap("AndroidManifest.xml",a.encode(change.apply(xml))));return out;}
 static byte[] message(Object... fields)throws Exception{ByteArrayOutputStream b=new ByteArrayOutputStream();CodedOutputStream out=CodedOutputStream.newInstance(b);for(int i=0;i<fields.length;i+=2){int n=(Integer)fields[i];Object v=fields[i+1];if(v instanceof byte[])out.writeByteArray(n,(byte[])v);else if(v instanceof String)out.writeString(n,(String)v);else out.writeUInt32(n,(Integer)v);}out.flush();return b.toByteArray();}
 static byte[] description(String path,int kind)throws Exception{return message(2,path,kind,new byte[0]);}
 public static void main(String[] args)throws Exception{
  root=new File(args[0],"apks");root.mkdirs();cache=new File(root,"cache");key=new File(args[2]);File fixtures=new File(args[1]);
  File baseRaw=new File(fixtures,"base.apk"),fr=new File(fixtures,"config-fr.apk");
  File main=CoreSmokeTest.assemble(root,"main","Main",12),featureDex=CoreSmokeTest.assemble(root,"feature","Feature",81);
  File base=new File(root,"base.apk");FileOps.rewriteZip(baseRaw,base,items("classes.dex",bytes(main),"assets/base.txt",utf("base data")));
  String featureXml="<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"demo.bundle\" android:versionCode=\"7\" split=\"feature\" android:isFeatureSplit=\"true\"><uses-sdk android:minSdkVersion=\"21\" android:targetSdkVersion=\"28\"/><application><activity android:name=\"demo.FeatureActivity\" android:splitName=\"feature\" android:exported=\"false\"/></application></manifest>";
  File feature=zip("feature.apk",items("AndroidManifest.xml",new Axml().encode(featureXml),"classes.dex",bytes(featureDex),"assets/feature.txt",utf("feature data"),"lib/arm64-v8a/libfixture.so",utf("test native payload")));
  File bundle=set("normal.apks",fr,feature,base);String original=FileOps.sha256(bundle);
  JSONObject info=ApksConverter.inspect(bundle);check(info.getJSONArray("choices").length()==1&&info.getJSONArray("choices").getJSONObject(0).getInt("count")==3,"nested SAI-style bundle is recognized without filename assumptions");
  JSONObject output=convert(bundle,"merged.apk",null);File merged=new File(output.getString("path"));
  check(output.getBoolean("merged")&&output.getBoolean("verified")&&output.getInt("apkCount")==3,"base, config and feature APKs merge into one verified APK");
  ApkVerifier.Result verified=new ApkVerifier.Builder(merged).build().verify();check(verified.isVerified()&&verified.isVerifiedUsingV1Scheme()&&verified.isVerifiedUsingV2Scheme()&&verified.isVerifiedUsingV3Scheme(),"merged output verifies V1, V2 and V3 signatures");
  check(original.equals(FileOps.sha256(bundle)),"original APKS is byte-identical after conversion");
  List<String> strings=Axml.resourceStrings(FileOps.zipEntry(merged,"resources.arsc",1000000));check(strings.contains("Base message")&&strings.contains("Bonjour split"),"binary resource merge retains default and French values");
  check(Arrays.equals(FileOps.zipEntry(merged,"assets/base.txt",100),utf("base data"))&&Arrays.equals(FileOps.zipEntry(merged,"assets/feature.txt",100),utf("feature data")),"base and feature assets survive");
  check(FileOps.zipEntry(merged,"lib/arm64-v8a/libfixture.so",100).length>0,"native library entry survives conversion");
  String xml=manifest(merged);check(xml.contains("demo.FeatureActivity")&&!xml.contains("splitName")&&!xml.contains("isFeatureSplit")&&!xml.contains(" split="),"feature components are merged and split-only manifest attributes removed");
  DexEngine dex=new DexEngine(new File(root,"dex"));dex.open(merged,new JSONArray().put("classes.dex").put("classes2.dex"));check(dex.classes.containsKey("Ldemo/Main;")&&dex.classes.containsKey("Ldemo/Feature;"),"DEX files are renumbered without losing classes");dex.close();
  check(ApksConverter.inspect(bundle).getString("fingerprint").equals(original),"inspection fingerprints the actual source archive");
  File unsigned=set("single.apks",base);JSONObject single=convert(unsigned,"single-signed.apk",null);check(!single.getBoolean("merged")&&!single.getBoolean("originalSignature")&&single.getBoolean("verified"),"unsigned standalone APK is signed and verified");
  File signed=new File(single.getString("path"));JSONObject originalCopy=convert(set("universal.apks",signed),"universal.apk",null);check(originalCopy.getBoolean("originalSignature")&&FileOps.sha256(signed).equals(FileOps.sha256(new File(originalCopy.getString("path")))),"valid standalone APK keeps its exact bytes and original signature");
  String hash=FileOps.sha256(merged);reject(()->convert(bundle,"merged.apk",null));check(hash.equals(FileOps.sha256(merged)),"existing output cannot be overwritten");
  try(InputStream in=new FileInputStream(key)){check(reject(()->ApksConverter.convert(bundle,new File(root,"stale.apk"),"split-set","stale",cache,in,null)).contains("changed")&&!new File(root,"stale.apk").exists(),"changed source fingerprint rejects stale conversion");}
  check(reject(()->convert(set("missing.apks",fr),"missing.apk",null)).contains("Missing base"),"missing base is rejected");
  check(reject(()->convert(set("two-base.apks",base,baseRaw),"two-base.apk",null)).contains("Multiple base"),"unrelated standalone variants are never merged together");
  File wrongPackage=changedManifest(feature,"wrong-package.apk",s->s.replace("demo.bundle","other.app"));check(reject(()->convert(set("wrong-package.apks",base,wrongPackage),"wrong-package-out.apk",null)).contains("different packages"),"mixed packages are rejected before merge");
  File wrongVersion=changedManifest(feature,"wrong-version.apk",s->s.replace("versionCode=\"7\"","versionCode=\"8\""));check(reject(()->convert(set("wrong-version.apks",base,wrongVersion),"wrong-version-out.apk",null)).contains("versions"),"mixed version codes are rejected");
  File noDexFeature=new File(root,"no-dex-feature.apk");FileOps.rewriteZip(fr,noDexFeature,Collections.emptyMap());
  check(reject(()->convert(set("duplicate-split.apks",base,fr,noDexFeature),"duplicate-split-out.apk",null)).contains("Duplicate split"),"duplicate split identities are rejected");
  File duplicateClass=new File(root,"duplicate-class.apk");FileOps.rewriteZip(feature,duplicateClass,Collections.singletonMap("classes.dex",bytes(main)));check(reject(()->convert(set("duplicate-class.apks",base,duplicateClass),"duplicate-class-out.apk",null)).contains("Conflicting DEX"),"duplicate DEX classes are rejected");
  File conflict=new File(root,"conflict.apk");FileOps.rewriteZip(feature,conflict,Collections.singletonMap("assets/base.txt",utf("different")));check(reject(()->convert(set("conflict.apks",base,conflict),"conflict-out.apk",null)).contains("Conflicting split contents"),"conflicting asset paths cannot silently overwrite each other");
  File dependent=changedManifest(feature,"dependent.apk",s->s.replace("<application", "<uses-split android:name=\"absent\"/><application"));check(reject(()->convert(set("dependent.apks",base,dependent),"dependent-out.apk",null)).contains("Missing required split"),"missing feature dependency rejects conversion");
  File incomplete=changedManifest(base,"incomplete.apk",s->s.replace("<application", "<application android:isSplitRequired=\"true\""));check(reject(()->convert(set("incomplete.apks",incomplete),"incomplete-out.apk",null)).contains("requires splits"),"a lone base requiring splits is not mislabeled a standalone APK");
  File required=changedManifest(base,"required.apk",s->s.replace("<manifest ","<manifest android:requiredSplitTypes=\"base__abi\" "));check(reject(()->convert(set("required.apks",required,fr),"required-out.apk",null)).contains("Missing required split types"),"required ABI or density split types are checked before removing split flags");
  File major=changedManifest(feature,"major.apk",s->s.replace("<manifest ","<manifest android:versionCodeMajor=\"2\" "));check(reject(()->convert(set("major.apks",base,major),"major-out.apk",null)).contains("versions"),"64-bit versionCodeMajor mismatches are rejected");
  File traversal=zip("traversal.apks",items("../base.apk",bytes(base)));check(reject(()->ApksConverter.inspect(traversal)).contains("Unsafe"),"archive traversal paths are rejected during inspection");
  File obb=zip("obb.apks",items("base.apk",bytes(base),"data/main.obb",utf("data")));check(reject(()->ApksConverter.inspect(obb)).contains("OBB"),"OBB content is not silently discarded");
  byte[] set0=message(2,description("splits/base.apk",3),2,description("splits/fr.apk",3));
  byte[] set1=message(2,description("standalone/universal.apk",4));
  byte[] toc=message(1,message(2,set0,3,0),1,message(2,set1,3,1));
  File multi=zip("variants.apks",items("toc.pb",toc,"splits/base.apk",bytes(base),"splits/fr.apk",bytes(fr),"standalone/universal.apk",bytes(signed)));
  check(ApksConverter.inspect(multi).getJSONArray("choices").length()==2,"bundletool TOC exposes separate split and standalone variants");
  JSONObject variant=convert(multi,"variant.apk","variant-0");check(variant.getInt("apkCount")==2,"only the chosen bundletool variant is merged");
  JSONObject stand=convert(multi,"standalone-variant.apk","variant-1-apk-0");check(stand.getBoolean("originalSignature"),"bundletool standalone variant is extracted and verified independently");
  File assetPack=zip("asset-pack.apks",items("toc.pb",message(1,message(2,set0),3,message(1,"assets")),"splits/base.apk",bytes(base),"splits/fr.apk",bytes(fr)));check(reject(()->ApksConverter.inspect(assetPack)).contains("Asset Delivery"),"Play asset packs get a clear unsupported error");
  reject(()->convert(multi,"invalid-choice.apk","not-a-variant"));check(!new File(root,"invalid-choice.apk").exists(),"unrecognized variant cannot produce an output");
  try(InputStream bad=new ByteArrayInputStream(new byte[]{1})){reject(()->ApksConverter.convert(bundle,new File(root,"bad-key.apk"),"split-set",original,cache,bad,null));}check(!new File(root,"bad-key.apk").exists(),"signing failure publishes no APK");
  check(cache.listFiles()!=null&&cache.listFiles().length==0&&Arrays.stream(root.listFiles()).noneMatch(f->f.getName().startsWith(".apks-output-")),"temporary extraction and publication files are cleaned after success and failure");
  System.out.println("ALL "+checks+" APKS CHECKS PASSED (JVM fixtures; Android installation not tested)");
 }
}
