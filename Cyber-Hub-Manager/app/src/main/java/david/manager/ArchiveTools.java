package david.manager;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.apache.commons.compress.archivers.tar.*;
import org.apache.commons.compress.archivers.sevenz.*;
import org.apache.commons.compress.compressors.gzip.*;
import org.apache.commons.compress.compressors.bzip2.*;
import org.apache.commons.compress.compressors.lz4.*;
import org.tukaani.xz.*;
import com.github.luben.zstd.*;
import net.lingala.zip4j.model.*;
import net.lingala.zip4j.model.enums.*;
import net.lingala.zip4j.io.outputstream.*;

/** Streaming archive operations. Output files are published only after writers close. */
public final class ArchiveTools {
 private ArchiveTools(){}
 static final List<String> FORMATS=Arrays.asList("zip","7z","tar","tar.gz","tar.xz","tar.zst","tar.bz2","tar.lz4","gzip");
 static class Item{File file;String name;Item(File f,String n){file=f;name=n;}}
 static void walk(File f,String name,List<Item> out,long[] size)throws Exception{
  if(Files.isSymbolicLink(f.toPath()))throw new IOException("Symbolic links are not archived");
  if(!f.exists())throw new IOException("Source missing: "+f);
  if(++size[1]>100000)throw new IOException("Too many source entries");
  out.add(new Item(f,name+(f.isDirectory()?"/":"")));
  if(f.isDirectory()){File[]fs=f.listFiles();if(fs==null)throw new IOException("Cannot read "+f);Arrays.sort(fs);for(File c:fs)walk(c,name+"/"+c.getName(),out,size);}
  else{size[0]+=f.length();if(size[0]>FileOps.MAX_EXTRACT)throw new IOException("Archive source exceeds 1 GB limit");}
 }
 static int level(String s){switch(s){case "store":return 0;case "fastest":return 1;case "fast":return 3;case "normal":return 5;case "maximum":return 7;case "ultra":return 9;case "apk":return 9;default:throw new IllegalArgumentException("Unknown compression level");}}
 public static JSONObject create(JSONObject a)throws Exception{
  String format=a.getString("format"),name=a.getString("name"),password=a.optString("password"),levelName=a.optString("level","normal");
  if(!FORMATS.contains(format))throw new IOException("Unsupported archive format");int level=level(levelName);
  if(!password.isEmpty()&&!format.equals("zip")&&!format.equals("7z"))throw new IOException("Password encryption is available for ZIP and 7z");
  if(levelName.equals("apk")&&!format.equals("zip"))throw new IOException("APK mode requires ZIP");
  File folder=new File(a.getString("destination")),dest=FileOps.child(folder,name);if(!folder.isDirectory())throw new IOException("Choose an existing output folder");if(dest.exists())throw new IOException("Output already exists");
  long split=a.optLong("splitBytes");if(split!=0&&(split<65536||split>FileOps.MAX_EXTRACT))throw new IOException("Split length must be 64 KB–1 GB");
  if(levelName.equals("apk")&&(!password.isEmpty()||split>0))throw new IOException("APK mode does not support passwords or split output");
  JSONArray paths=a.getJSONArray("paths");if(paths.length()==0)throw new IOException("Select source files");List<File>sources=new ArrayList<>();Set<String>names=new HashSet<>();List<Item>items=new ArrayList<>();long[]stats={0,0};
  for(int i=0;i<paths.length();i++){File f=new File(paths.getString(i));if(!names.add(f.getName()))throw new IOException("Duplicate top-level source name");if(dest.getCanonicalFile().toPath().startsWith(f.getCanonicalFile().toPath()))throw new IOException("Archive cannot be inside a source folder");sources.add(f);walk(f,f.getName(),items,stats);}
  if(format.equals("gzip")&&(items.size()!=1||!items.get(0).file.isFile()))throw new IOException("gzip accepts one file. Choose tar.gz for multiple files/folders.");
  File stage=new File(folder,".cyber-archive-"+UUID.randomUUID());if(!stage.mkdir())throw new IOException("Cannot create output staging folder");List<File>published=new ArrayList<>();
  try{
   File output=new File(stage,name);
   if(format.equals("zip"))writeZip(items,output,password,level,levelName.equals("apk"),split);
   else if(format.equals("7z"))write7z(items,output,password,level);
   else if(format.equals("gzip")){try(OutputStream out=compress(new FileOutputStream(output),format,level);InputStream in=new FileInputStream(items.get(0).file)){FileOps.copy(in,out,FileOps.MAX_EXTRACT);}}
   else{try(OutputStream compressed=compress(new FileOutputStream(output),format,level);TarArchiveOutputStream out=new TarArchiveOutputStream(compressed)){
    out.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);out.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
    for(Item item:items){TarArchiveEntry entry=new TarArchiveEntry(item.file,item.name);out.putArchiveEntry(entry);if(item.file.isFile())try(InputStream in=new FileInputStream(item.file)){FileOps.copy(in,out,FileOps.MAX_EXTRACT);}out.closeArchiveEntry();}
   }}
   if(split>0&&!format.equals("zip"))split(output,split);
   File[]produced=stage.listFiles();if(produced==null||produced.length==0)throw new IOException("No archive produced");Arrays.sort(produced);
   for(File f:produced)if(new File(folder,f.getName()).exists())throw new IOException("Output part already exists: "+f.getName());
   for(File f:produced){File target=new File(folder,f.getName());Files.move(f.toPath(),target.toPath());published.add(target);}
  }catch(Exception e){for(File f:published)f.delete();throw e;}finally{FileOps.deleteTree(stage);}
  JSONArray outputs=new JSONArray();for(File f:published)outputs.put(f.getPath());return new JSONObject().put("outputs",outputs).put("sources",paths).put("size",stats[0]);
 }
 static void writeZip(List<Item>items,File dest,String password,int level,boolean apk,long split)throws Exception{
  try(SplitOutputStream sink=new SplitOutputStream(dest,split>0?split:-1);ZipOutputStream out=new ZipOutputStream(sink,password.isEmpty()?null:password.toCharArray())){
   for(Item i:items){ZipParameters p=new ZipParameters();p.setFileNameInZip(i.name);p.setLastModifiedFileTime(i.file.lastModified());p.setEntrySize(i.file.isFile()?i.file.length():0);
    boolean stored=level==0||i.file.isDirectory()||apk&&(i.name.endsWith(".arsc")||i.name.endsWith(".so"));p.setCompressionMethod(stored?CompressionMethod.STORE:CompressionMethod.DEFLATE);p.setCompressionLevel((level<=1?CompressionLevel.FASTEST:level<=3?CompressionLevel.FAST:level<=5?CompressionLevel.NORMAL:level<=7?CompressionLevel.MAXIMUM:CompressionLevel.ULTRA));
    if(!password.isEmpty()){p.setEncryptFiles(true);p.setEncryptionMethod(EncryptionMethod.AES);p.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);}
    out.putNextEntry(p);if(i.file.isFile())try(InputStream in=new FileInputStream(i.file)){FileOps.copy(in,out,FileOps.MAX_EXTRACT);}out.closeEntry();
   }
  }
  if(apk){File aligned=new File(dest.getParentFile(),".aligned");FileOps.rewriteZip(dest,aligned,Collections.emptyMap());FileOps.replace(aligned,dest);}
 }
 static void write7z(List<Item>items,File dest,String password,int level)throws Exception{
  try(SevenZOutputFile out=new SevenZOutputFile(dest,password.isEmpty()?null:password.toCharArray())){
   LZMA2Options options=new LZMA2Options(level);options.setDictSize(level>=7?16*1024*1024:level>=5?8*1024*1024:2*1024*1024);
   out.setContentMethods(Collections.singletonList(level==0?new SevenZMethodConfiguration(SevenZMethod.COPY):new SevenZMethodConfiguration(SevenZMethod.LZMA2,options)));
   for(Item i:items){out.putArchiveEntry(out.createArchiveEntry(i.file,i.name));if(i.file.isFile())try(InputStream in=new FileInputStream(i.file)){byte[]b=new byte[32768];int n;while((n=in.read(b))!=-1)out.write(b,0,n);}out.closeArchiveEntry();}
  }
 }
 static OutputStream compress(OutputStream out,String format,int level)throws Exception{
  if(format.equals("tar"))return out;
  if(format.equals("tar.gz")||format.equals("gzip")){GzipParameters p=new GzipParameters();p.setCompressionLevel(level);return new GzipCompressorOutputStream(out,p);}
  if(format.equals("tar.xz")){LZMA2Options p=new LZMA2Options(level);p.setDictSize(level>=7?16*1024*1024:level>=5?8*1024*1024:2*1024*1024);if(level==0)p.setMode(LZMA2Options.MODE_UNCOMPRESSED);return new XZOutputStream(out,p);}
  if(format.equals("tar.bz2"))return new BZip2CompressorOutputStream(out,Math.max(1,level));
  if(format.equals("tar.lz4"))return new FramedLZ4CompressorOutputStream(out);
  if(format.equals("tar.zst"))return new ZstdOutputStream(out,level==0?1:level*2);
  throw new IOException("Unknown compressor");
 }
 static void split(File file,long length)throws Exception{try(InputStream in=new FileInputStream(file)){byte[]buf=new byte[32768];int part=1,n;while((n=in.read(buf))!=-1){File f=new File(file.getPath()+String.format(Locale.ROOT,".%03d",part++));try(OutputStream out=new FileOutputStream(f)){long left=length;while(n!=-1){int take=(int)Math.min(n,left);out.write(buf,0,take);left-=take;if(take<n)throw new IOException("Split buffer boundary mismatch");if(left==0)break;n=in.read(buf,0,(int)Math.min(buf.length,left));}}}}if(!file.delete())throw new IOException("Cannot finish split archive");}
 static String format(File f){String n=f.getName().toLowerCase(Locale.ROOT).replaceFirst("\\.001$","");for(String ext:Arrays.asList("tar.gz","tar.xz","tar.zst","tar.bz2","tar.lz4","7z","tar","zip","apk"))if(n.endsWith("."+ext))return ext;if(n.endsWith(".gz")||n.endsWith(".gzip"))return "gzip";return "zip";}
 static InputStream decompress(File f,String format)throws Exception{InputStream in=new BufferedInputStream(new FileInputStream(f));try{switch(format){case "tar":return in;case "tar.gz":case "gzip":return new GzipCompressorInputStream(in);case "tar.xz":return new XZInputStream(in,128*1024);case "tar.bz2":return new BZip2CompressorInputStream(in);case "tar.lz4":return new FramedLZ4CompressorInputStream(in);case "tar.zst":return new ZstdInputStream(in);default:throw new IOException("Unknown archive type");}}catch(Exception e){in.close();throw e;}}
 public static void extract(File input,File dest,String password)throws Exception{
  if(dest.exists())throw new IOException("Extraction folder already exists");if(!dest.mkdirs())throw new IOException("Cannot create extraction folder");
  File merged=null,src=input;long[]count={0,0};String format=format(input);
  try{
   if(input.getName().endsWith(".001")){merged=File.createTempFile(".joined-",".tmp",dest.getParentFile());String base=input.getPath().substring(0,input.getPath().length()-4);long total=0;try(OutputStream out=new FileOutputStream(merged)){for(int i=1;i<10000;i++){File part=new File(base+String.format(Locale.ROOT,".%03d",i));if(!part.exists())break;try(InputStream in=new FileInputStream(part)){total+=FileOps.copy(in,out,FileOps.MAX_EXTRACT-total);}}}src=merged;}
   if(format.equals("zip")||format.equals("apk")){
    try(net.lingala.zip4j.ZipFile z=new net.lingala.zip4j.ZipFile(src,password.toCharArray())){for(FileHeader h:z.getFileHeaders()){File f=output(dest,h.getFileName(),h.isDirectory(),count);if(h.isDirectory())continue;try(InputStream in=z.getInputStream(h);OutputStream out=new FileOutputStream(f)){count[0]+=FileOps.copy(in,out,FileOps.MAX_EXTRACT-count[0]);}}}
   }else if(format.equals("7z")){
    try(SevenZFile z=SevenZFile.builder().setFile(src).setPassword(password.toCharArray()).setMaxMemoryLimitKiB(128*1024).get()){
     SevenZArchiveEntry e;while((e=z.getNextEntry())!=null){File f=output(dest,e.getName(),e.isDirectory(),count);if(e.isDirectory())continue;try(OutputStream out=new FileOutputStream(f)){byte[]b=new byte[32768];int n;while((n=z.read(b))!=-1){count[0]+=n;if(count[0]>FileOps.MAX_EXTRACT)throw new IOException("Extraction exceeds 1 GB");out.write(b,0,n);}}}
    }
   }else if(format.equals("gzip")){String name=input.getName().replaceFirst("\\.(gz|gzip)(\\.001)?$","");File f=output(dest,name,false,count);try(InputStream in=decompress(src,format);OutputStream out=new FileOutputStream(f)){FileOps.copy(in,out,FileOps.MAX_EXTRACT);}}
   else{try(TarArchiveInputStream in=new TarArchiveInputStream(decompress(src,format))){TarArchiveEntry e;while((e=in.getNextEntry())!=null){if(!e.isFile()&&!e.isDirectory())throw new IOException("Links and special archive entries are not extracted");File f=output(dest,e.getName(),e.isDirectory(),count);if(e.isDirectory())continue;try(OutputStream out=new FileOutputStream(f)){count[0]+=FileOps.copy(in,out,FileOps.MAX_EXTRACT-count[0]);}}}}
  }catch(Exception e){FileOps.deleteTree(dest);throw e;}finally{if(merged!=null)merged.delete();}
 }
 static File output(File dest,String name,boolean directory,long[]count)throws Exception{
  if(name==null||++count[1]>100000)throw new IOException("Invalid/too many archive entries");File f=FileOps.contained(dest,name);
  if(directory){if(!f.isDirectory()&&!f.mkdirs())throw new IOException("Cannot create directory");}
  else{if(f.exists())throw new IOException("Duplicate archive path: "+name);if(!f.getParentFile().isDirectory()&&!f.getParentFile().mkdirs())throw new IOException("Cannot create directory");}return f;
 }
}
