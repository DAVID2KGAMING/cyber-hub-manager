package david.manager;

import android.content.*;import android.content.pm.*;import android.os.*;
import org.json.*;import java.io.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.text.*;import java.util.*;import java.util.zip.*;
import com.android.apksig.*;

public final class DataEngine {
 final MainActivity activity;final File workspace,cache,trash;final DexEngine dex;final Map<String,Doc> documents=new HashMap<>();final Map<String,Map<String,byte[]>> archiveEdits=new HashMap<>();final Map<String,File> archiveOutputs=new HashMap<>();final LocalService services;private long docCounter=0;
 static class Doc {File file;String archive,entry;Axml axml;long modified;}
 DataEngine(MainActivity a){activity=a;workspace=new File(a.getFilesDir(),"Workspace");workspace.mkdirs();cache=new File(a.getCacheDir(),"entries");cache.mkdirs();trash=new File(a.getFilesDir(),"recycle");trash.mkdirs();dex=new DexEngine(new File(a.getCacheDir(),"dex"));services=new LocalService(workspace);
  ApkTools.loadKey(a.getFilesDir());
  File welcome=new File(workspace,"Welcome.txt");if(!welcome.exists())try{FileOps.writeAtomic(welcome,("DB Manager 0.1\n\nChoose Grant file access to browse your phone.\nTap a file to open it. Long press for copy, move, rename or recycle.\nAPK: view contents, edit manifest, open DEX, view Java/Smali.\nEdits create backups or a separate edited archive.\nJava and Smali are editable. Save compiles changes. Save and sign APK verifies signatures and keeps a backup.\n\nNetwork servers run only while this app process remains active.\n").getBytes(StandardCharsets.UTF_8),false);}catch(Exception ignored){}
 }
 boolean permission(){return Build.VERSION.SDK_INT>=30?Environment.isExternalStorageManager():activity.checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)==PackageManager.PERMISSION_GRANTED;}
 synchronized Object call(String action,JSONObject a)throws Exception{
  switch(action){
   case "init":return new JSONObject().put("permission",permission()).put("home",Environment.getExternalStorageDirectory().getPath()).put("workspace",workspace.getPath()).put("version","0.2.3").put("ownApk",activity.getApplicationInfo().sourceDir);
   case "list":return list(a);
   case "disk":{File f=new File(a.getString("path"));return new JSONObject().put("total",f.getTotalSpace()).put("free",f.getUsableSpace());}
   case "exportText":{File f=FileOps.child(new File(a.getString("path")),a.getString("name"));if(f.exists())throw new IOException("Output already exists");FileOps.writeAtomic(f,a.getString("text").getBytes(StandardCharsets.UTF_8),false);record("Exported "+f);return f.getPath();}
   case "read":return read(a);
   case "save":return save(a);
   case "pool":{byte[] b=FileOps.read(resolve(a),32L*1024*1024);List<String>ss=Axml.isBinary(b)?Axml.resourceStrings(b):Axml.resourceStrings(b);return new JSONArray(ss);}
   case "resolve":return resolve(a).getPath();
   case "create":{File f=FileOps.child(new File(a.getString("path")),a.getString("name"));if(f.exists())throw new IOException("Name already exists");if(a.optBoolean("folder")){if(!f.mkdir())throw new IOException("Cannot create folder");}else FileOps.writeAtomic(f,new byte[0],false);record("Created "+f);return f.getPath();}
   case "batchRename":{Object r=BatchFiles.rename(a.getJSONArray("files"));record("Renamed selected files");return r;}
   case "batchTransfer":{JSONArray fs=a.getJSONArray("files");List<File>sources=new ArrayList<>();List<String>names=new ArrayList<>();boolean move=a.optBoolean("move");for(int i=0;i<fs.length();i++){JSONObject f=fs.getJSONObject(i);if(move&&!f.optString("archive").isEmpty())throw new IOException("Extract archive entries before moving");sources.add(resolve(f));names.add(f.getString("name"));}Object r=BatchFiles.transfer(sources,names,new File(a.getString("destination")),move);record((move?"Moved ":"Copied ")+sources.size()+" selected files");return r;}
   case "rename":{File old=new File(a.getString("path"));File dest=FileOps.child(old.getParentFile(),a.getString("name"));if(dest.exists())throw new IOException("Name already exists");Files.move(old.toPath(),dest.toPath());record("Renamed "+old.getName()+" → "+dest.getName());return dest.getPath();}
   case "copy":case "move":{File src=resolve(a),dst=FileOps.child(new File(a.getString("destination")),src.getName());FileOps.copyTree(src,dst);if(action.equals("move"))FileOps.deleteTree(src);record(action+" "+src+" → "+dst);return dst.getPath();}
   case "trash":return recycle(new File(a.getString("path")));
   case "recycleList":return recycleList();
   case "restore":{File meta=FileOps.child(trash,a.getString("id")+".json");JSONObject m=new JSONObject(new String(FileOps.read(meta,65536),StandardCharsets.UTF_8));File src=FileOps.child(trash,a.getString("id")),dst=new File(m.getString("path"));if(dst.exists())throw new IOException("Original path is occupied");FileOps.copyTree(src,dst);FileOps.deleteTree(src);meta.delete();record("Restored "+dst);return true;}
   case "purge":{FileOps.deleteTree(FileOps.child(trash,a.getString("id")));FileOps.child(trash,a.getString("id")+".json").delete();return true;}
   case "extract":{File f=resolve(a),dst=FileOps.child(new File(a.getString("destination")),a.getString("name"));FileOps.extract(f,dst);record("Extracted "+f.getName());return dst.getPath();}
   case "compress":{JSONObject r=ArchiveTools.create(a);JSONArray removed=new JSONArray(),failures=new JSONArray();if(a.optBoolean("deleteSources")){JSONArray paths=a.getJSONArray("paths");for(int i=0;i<paths.length();i++){String path=paths.getString(i);try{recycle(new File(path));removed.put(path);}catch(Exception e){failures.put(path+": "+e.getMessage());}}}r.put("removed",removed).put("cleanupErrors",failures);record("Created archive "+r.getJSONArray("outputs"));return r;}
   case "archiveExtract":{File src=resolve(a),dest=FileOps.child(new File(a.getString("destination")),a.getString("name"));ArchiveTools.extract(src,dest,a.optString("password"));record("Extracted "+src);return dest.getPath();}
   case "compare":return CompareTools.compare(new File(a.getString("left")),new File(a.getString("right")),a.getString("mode"));
   case "zip":{File f=new File(a.getString("path")),dst=FileOps.child(f.getParentFile(),a.getString("name"));FileOps.zip(f,dst);record("Archived "+f.getName());return dst.getPath();}
   case "properties":{File f=resolve(a);return new JSONObject().put("path",f.getPath()).put("size",f.length()).put("modified",f.lastModified()).put("readable",f.canRead()).put("writable",f.canWrite()).put("sha256",f.isFile()?FileOps.sha256(f):"—");}
   case "apkInfo":return apkInfo(resolve(a));
   case "bundleInspect":return ApksConverter.inspect(resolve(a));
   case "bundleConvert":{File src=resolve(a),dst=FileOps.child(new File(a.getString("destination")),a.getString("name"));try(InputStream key=activity.getAssets().open("development-signing.p12")){JSONObject result=ApksConverter.convert(src,dst,a.getString("choice"),a.getString("fingerprint"),new File(activity.getCacheDir(),"bundle-conversion"),key,message->activity.bundleProgress(a.optString("job"),message));record("Converted APKS to "+dst);return result;}}
   case "apkIcon":return iconForPath(a.getString("path"));
   case "sign":{File src=new File(a.getString("path")),dst=FileOps.child(new File(a.optString("destination",src.getParentFile().canWrite()?src.getParent():workspace.getPath())),strip(src.getName())+"-signed.apk");int suffix=2;while(dst.exists())dst=FileOps.child(dst.getParentFile(),strip(src.getName())+"-signed-"+(suffix++)+".apk");sign(src,dst);record("Signed "+dst.getName());return dst.getPath();}
   case "dexFiles":return dexFiles(resolve(a));
   case "dexOpen":return dex.open(resolve(a),a.getJSONArray("entries"));
   case "dexTree":return dex.tree(a.optString("prefix"));
   case "dexCode":return dex.code(a.getString("class"),a.optString("mode","smali"),a.optString("decompiler","auto"));
   case "dexSave":{Object out=dex.save(a.getString("class"),a.getString("text"));record("Saved Smali "+a.getString("class"));return out;}
   case "dexJavaSave":{File api=new File(activity.getCacheDir(),"compiler-api-34.jar");if(!api.isFile())try(InputStream in=activity.getAssets().open("compiler/android-api.jar")){FileOps.writeAtomic(api,FileOps.bytes(in,16L*1024*1024),false);}Object out=dex.saveJava(a.getString("class"),a.getString("text"),api);record("Compiled Java "+a.getString("class"));return out;}
   case "dexExport":{File output=new File(a.getString("destination"));Object out=dex.export(output);record("Exported DEX changes");return out;}
   case "dexQuery":return dex.query(a);
   case "dexSaveSign":{try(InputStream key=activity.getAssets().open("development-signing.p12")){JSONObject r=dex.commit(key);record("Saved, signed and verified "+r.getString("path"));return r;}}
   case "dexCommit":{JSONObject r=dex.commit();record("Saved DEX project to "+r.getString("path"));return r;}
   case "restoreBackup":{File f=FileOps.restoreBackup(new File(a.getString("path")));record("Restored backup "+f);return f.getPath();}
   case "dexStrings":return dex.strings(a.optString("query"));
   case "dexSearch":return dex.search(a.optString("query"));
   case "apps":return apps();
   case "log":return new JSONArray(activity.getPreferences(0).getString("log","[]"));
   case "terminal":return terminal(a.getString("command"),a.optString("path",workspace.getPath()));
   case "plugins":return plugins(a);
   case "service":return services.action(a);
   case "ftp":return FtpTools.call(a);
   case "apkTool":return apkToolHost(a);
   default:throw new IOException("Unknown operation: "+action);
  }
 }
 static String strip(String name){int p=name.lastIndexOf('.');return p>0?name.substring(0,p):name;}
 File resolve(JSONObject a)throws Exception{
  String archive=a.optString("archive");if(archive.isEmpty())return new File(a.getString("path"));String entry=a.getString("entry");String token=Integer.toHexString((archive+"|"+entry).hashCode());File dir=new File(cache,token);dir.mkdirs();File f=FileOps.child(dir,new File(entry).getName());byte[] bytes=FileOps.zipEntry(new File(archive),entry,256L*1024*1024);FileOps.writeAtomic(f,bytes,false);return f;
 }
 JSONArray list(JSONObject a)throws Exception{
  JSONArray out=new JSONArray();String archive=a.optString("archive");if(!archive.isEmpty()){
   String prefix=a.optString("entry");if(!prefix.isEmpty()&&!prefix.endsWith("/"))prefix+="/";Map<String,JSONObject>items=new TreeMap<>();
   try(ZipFile z=new ZipFile(archive)){Enumeration<? extends ZipEntry>en=z.entries();while(en.hasMoreElements()){ZipEntry e=en.nextElement();String name=e.getName();if(!name.startsWith(prefix)||name.equals(prefix))continue;String rest=name.substring(prefix.length());int slash=rest.indexOf('/');boolean dir=slash>=0;String shortName=dir?rest.substring(0,slash):rest;if(shortName.isEmpty())continue;items.put(shortName,new JSONObject().put("name",shortName).put("dir",dir).put("size",dir?0:e.getSize()).put("time",e.getTime()).put("archive",archive).put("entry",prefix+shortName+(dir?"/":"")));}}
   List<JSONObject>vals=new ArrayList<>(items.values());vals.sort((x,y)->Boolean.compare(y.optBoolean("dir"),x.optBoolean("dir")));for(JSONObject v:vals)out.put(v);
  }else{File dir=new File(a.getString("path"));File[] files=dir.listFiles();if(files==null)throw new IOException("Cannot read this folder. Grant file access or choose an accessible directory.");Arrays.sort(files,(x,y)->x.isDirectory()!=y.isDirectory()?(x.isDirectory()?-1:1):x.getName().compareToIgnoreCase(y.getName()));long free=dir.getUsableSpace(),total=dir.getTotalSpace();for(File f:files){if(!a.optBoolean("hidden")&&f.getName().startsWith("."))continue;out.put(new JSONObject().put("name",f.getName()).put("path",f.getPath()).put("dir",f.isDirectory()).put("size",f.length()).put("time",f.lastModified()).put("free",free).put("total",total));}}
  return out;
 }
 JSONObject read(JSONObject a)throws Exception{
  File f=resolve(a);byte[] b=FileOps.read(f,FileOps.MAX_TEXT);Doc d=new Doc();d.file=f;d.archive=a.optString("archive");d.entry=a.optString("entry");d.modified=f.lastModified();String text;
  if(Axml.isBinary(b)){d.axml=new Axml();text=d.axml.decode(b);}else{for(int n=0;n<Math.min(b.length,2048);n++)if(b[n]==0)throw new IOException("Binary file: use APK, DEX or resource tools");text=new String(b,StandardCharsets.UTF_8);}
  String id="doc"+(++docCounter);documents.put(id,d);return new JSONObject().put("id",id).put("text",text).put("name",f.getName()).put("path",f.getPath()).put("binaryXml",d.axml!=null);
 }
 JSONObject save(JSONObject a)throws Exception{
  Doc d=documents.get(a.getString("id"));if(d==null)throw new IOException("Document session expired");if(d.file.lastModified()!=d.modified)throw new IOException("File changed externally; reload before saving");String text=a.getString("text");byte[] bytes=d.axml==null?text.getBytes(StandardCharsets.UTF_8):d.axml.encode(text);FileOps.writeAtomic(d.file,bytes,true);d.modified=d.file.lastModified();File output=d.file;
  if(!d.archive.isEmpty()){
   Map<String,byte[]>edits=archiveEdits.computeIfAbsent(d.archive,k->new HashMap<>());edits.put(d.entry,bytes);output=archiveOutputs.get(d.archive);
   if(output==null){File src=new File(d.archive);File parent=src.getParentFile().canWrite()?src.getParentFile():workspace;String ext=src.getName().endsWith(".apk")?".apk":".zip";output=new File(parent,strip(src.getName())+"-edited"+ext);int n=2;while(output.exists())output=new File(parent,strip(src.getName())+"-edited-"+(n++)+ext);archiveOutputs.put(d.archive,output);}
   FileOps.rewriteZip(new File(d.archive),output,edits);
  }record("Saved "+output);return new JSONObject().put("path",output.getPath()).put("needsSigning",output.getName().endsWith(".apk"));
 }
 String recycle(File f)throws Exception{
  if(!f.exists())throw new IOException("File no longer exists");String id=UUID.randomUUID().toString();File target=new File(trash,id);FileOps.copyTree(f,target);JSONObject meta=new JSONObject().put("path",f.getCanonicalPath()).put("name",f.getName()).put("time",System.currentTimeMillis()).put("id",id);FileOps.writeAtomic(new File(trash,id+".json"),meta.toString().getBytes(StandardCharsets.UTF_8),false);FileOps.deleteTree(f);record("Recycled "+f.getName());return id;
 }
 JSONArray recycleList()throws Exception{JSONArray arr=new JSONArray();File[] fs=trash.listFiles();if(fs!=null)for(File f:fs)if(f.getName().endsWith(".json"))arr.put(new JSONObject(new String(FileOps.read(f,65536),StandardCharsets.UTF_8)));return arr;}
 JSONObject apkInfo(File f)throws Exception{
  PackageManager pm=activity.getPackageManager();PackageInfo p=pm.getPackageArchiveInfo(f.getPath(),PackageManager.GET_PERMISSIONS);if(p==null)throw new IOException("Android could not parse this APK");p.applicationInfo.sourceDir=f.getPath();p.applicationInfo.publicSourceDir=f.getPath();String sig="Unsigned / unverified";
  try{ApkVerifier.Result v=new ApkVerifier.Builder(f).build().verify();List<String>s=new ArrayList<>();if(v.isVerifiedUsingV1Scheme())s.add("V1");if(v.isVerifiedUsingV2Scheme())s.add("V2");if(v.isVerifiedUsingV3Scheme())s.add("V3");sig=v.isVerified()?String.join(" + ",s):"Invalid or unsigned";}catch(Exception e){sig="Could not verify: "+e.getMessage();}
  return new JSONObject().put("icon",appIcon(p.applicationInfo)).put("name",String.valueOf(p.applicationInfo.loadLabel(pm))).put("package",p.packageName).put("version",p.versionName).put("versionCode",Build.VERSION.SDK_INT>=28?p.getLongVersionCode():p.versionCode).put("size",f.length()).put("signature",sig).put("minSdk",p.applicationInfo.minSdkVersion).put("targetSdk",p.applicationInfo.targetSdkVersion).put("path",f.getPath());
 }
 String iconForPath(String path){PackageInfo info=activity.getPackageManager().getPackageArchiveInfo(path,0);if(info==null||info.applicationInfo==null)return "";info.applicationInfo.sourceDir=path;info.applicationInfo.publicSourceDir=path;return appIcon(info.applicationInfo);}
 String appIcon(ApplicationInfo info){try{android.graphics.drawable.Drawable drawable=info.loadIcon(activity.getPackageManager());android.graphics.Bitmap bitmap=android.graphics.Bitmap.createBitmap(96,96,android.graphics.Bitmap.Config.ARGB_8888);android.graphics.Canvas canvas=new android.graphics.Canvas(bitmap);drawable.setBounds(0,0,96,96);drawable.draw(canvas);ByteArrayOutputStream out=new ByteArrayOutputStream();bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,out);bitmap.recycle();return "data:image/png;base64,"+android.util.Base64.encodeToString(out.toByteArray(),android.util.Base64.NO_WRAP);}catch(Exception e){return "";}}
 void sign(File src,File dst)throws Exception{try(InputStream key=activity.getAssets().open("development-signing.p12")){ApkSigning.sign(src,dst,key);}}
 JSONArray dexFiles(File f)throws Exception{JSONArray a=new JSONArray();if(f.getName().endsWith(".dex"))return a.put(f.getName());try(ZipFile z=new ZipFile(f)){Enumeration<? extends ZipEntry>en=z.entries();while(en.hasMoreElements()){String n=en.nextElement().getName();if(n.matches("classes[0-9]*\\.dex"))a.put(n);}}return a;}
 JSONArray apps()throws Exception{JSONArray a=new JSONArray();List<ApplicationInfo>apps=activity.getPackageManager().getInstalledApplications(0);apps.sort((x,y)->String.valueOf(x.loadLabel(activity.getPackageManager())).compareToIgnoreCase(String.valueOf(y.loadLabel(activity.getPackageManager()))));for(ApplicationInfo p:apps)a.put(new JSONObject().put("name",String.valueOf(p.loadLabel(activity.getPackageManager()))).put("package",p.packageName).put("path",p.sourceDir));return a;}
 void record(String text){try{JSONArray old=new JSONArray(activity.getPreferences(0).getString("log","[]"));JSONArray next=new JSONArray();next.put(new JSONObject().put("text",text).put("time",System.currentTimeMillis()));for(int i=0;i<Math.min(199,old.length());i++)next.put(old.get(i));activity.getPreferences(0).edit().putString("log",next.toString()).apply();}catch(Exception ignored){}}
 String terminal(String command,String path)throws Exception{if(command.trim().isEmpty())return "";File dir=new File(path);if(!dir.isDirectory())throw new IOException("Choose a normal folder first");java.lang.Process p=new ProcessBuilder("/system/bin/sh","-c",command).directory(dir).redirectErrorStream(true).start();java.util.concurrent.ExecutorService one=java.util.concurrent.Executors.newSingleThreadExecutor();java.util.concurrent.Future<byte[]>future=one.submit(()->FileOps.bytes(p.getInputStream(),1024*1024));try{if(!p.waitFor(20,java.util.concurrent.TimeUnit.SECONDS)){p.destroyForcibly();throw new IOException("Command timed out after 20 seconds");}String result=new String(future.get(2,java.util.concurrent.TimeUnit.SECONDS),StandardCharsets.UTF_8);record("Terminal command completed (exit "+p.exitValue()+")");return result+"\n[exit "+p.exitValue()+"]";}finally{p.destroy();one.shutdownNow();}}
 Object plugins(JSONObject a)throws Exception{File dir=new File(workspace,"Plugins");dir.mkdirs();String op=a.optString("op","list");if(op.equals("import")){File src=new File(a.getString("path"));if(!src.getName().endsWith(".sh"))throw new IOException("Plugins must be .sh scripts");FileOps.copyTree(src,FileOps.child(dir,src.getName()));record("Imported script plugin "+src.getName());return true;}if(op.equals("run")){File f=FileOps.child(dir,a.getString("name"));return terminal("/system/bin/sh '"+f.getPath().replace("'","'\\''")+"'",workspace.getPath());}if(op.equals("remove")){FileOps.deleteTree(FileOps.child(dir,a.getString("name")));return true;}JSONArray arr=new JSONArray();File[]fs=dir.listFiles();if(fs!=null)for(File f:fs)if(f.getName().endsWith(".sh"))arr.put(f.getName());return arr;}
 Object apkToolHost(JSONObject a)throws Exception{
  ApkTools.Host h=new ApkTools.Host(){
   public File workspace(){return workspace;}
   public void sign(File s,File d)throws Exception{DataEngine.this.sign(s,d);}
   public void record(String t){DataEngine.this.record(t);}
   public File androidApiJar()throws Exception{File api=new File(activity.getCacheDir(),"compiler-api-34.jar");if(!api.isFile())try(InputStream in=activity.getAssets().open("compiler/android-api.jar")){FileOps.writeAtomic(api,FileOps.bytes(in,16L*1024*1024),false);}return api;}
   public byte[] devSigningCert()throws Exception{
    byte[] p12=ApkSigning.customP12;char[] pass=ApkSigning.customPass;
    java.security.KeyStore ks=java.security.KeyStore.getInstance("PKCS12");
    if(p12!=null){ks.load(new ByteArrayInputStream(p12),pass);}
    else{try(InputStream in=activity.getAssets().open("development-signing.p12")){ks.load(in,"cyberhub-development".toCharArray());}}
    String alias=ApkSigning.firstKey(ks);
    java.security.cert.X509Certificate c=(java.security.cert.X509Certificate)ks.getCertificate(alias);
    return java.security.MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
   }
  };
  return ApkTools.call(h,a);
 }
 void close(){services.stop();dex.close();}
}
