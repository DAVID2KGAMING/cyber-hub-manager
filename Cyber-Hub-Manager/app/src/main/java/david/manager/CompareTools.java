package david.manager;
import java.io.*;import java.util.*;import java.util.zip.*;import org.json.*;import java.nio.charset.StandardCharsets;
import org.jf.dexlib2.*;import org.jf.dexlib2.dexbacked.*;import org.jf.dexlib2.iface.*;import org.jf.baksmali.*;import org.jf.baksmali.Adaptors.*;import org.jf.baksmali.formatter.*;
public final class CompareTools {
 private CompareTools(){}
 public static JSONObject compare(File left,File right,String mode)throws Exception{
  SortedMap<String,String>a=values(left,mode),b=values(right,mode);SortedSet<String>keys=new TreeSet<>(a.keySet());keys.addAll(b.keySet());JSONArray rows=new JSONArray();int added=0,removed=0,changed=0,same=0;
  for(String k:keys){String x=a.get(k),y=b.get(k);String status;if(x==null){status="Added";added++;}else if(y==null){status="Removed";removed++;}else if(!x.equals(y)){status="Changed";changed++;}else{same++;continue;}
   if(rows.length()<2000)rows.put(new JSONObject().put("name",k).put("status",status).put("left",preview(x)).put("right",preview(y)));
  }
  return new JSONObject().put("rows",rows).put("added",added).put("removed",removed).put("changed",changed).put("same",same).put("truncated",added+removed+changed>rows.length());
 }
 static String digest(byte[]b,int start,int length)throws Exception{java.security.MessageDigest md=java.security.MessageDigest.getInstance("SHA-256");md.update(b,start,length);StringBuilder h=new StringBuilder();for(byte x:md.digest())h.append(String.format("%02x",x&255));return length+" bytes; SHA-256 "+h;}
 static int u16(byte[]b,int n){return (b[n]&255)|((b[n+1]&255)<<8);}
 static long u32(byte[]b,int n){return (b[n]&255L)|((b[n+1]&255L)<<8)|((b[n+2]&255L)<<16)|((b[n+3]&255L)<<24);}
 static void resourceChunks(byte[]b,int start,int end,String prefix,SortedMap<String,String>map)throws Exception{
  Map<Integer,Integer>counts=new HashMap<>();for(int pos=start;pos<end;){if(pos+8>end)throw new IOException("Truncated resource chunk");int type=u16(b,pos),header=u16(b,pos+2);long length=u32(b,pos+4);if(header<8||length<header||pos+length>end)throw new IOException("Invalid resource chunk size");int size=(int)length,index=counts.getOrDefault(type,0);counts.put(type,index+1);String key=prefix+"/"+String.format(Locale.ROOT,"%04x[%d]",type,index);
   if(type==0x0002||type==0x0200){map.put(key+"/header",digest(b,pos,header));resourceChunks(b,pos+header,pos+size,key,map);}else map.put(key,digest(b,pos,size));pos+=size;
  }
 }
 static String preview(String s){return s==null?"(absent)":s.length()>16000?s.substring(0,16000)+"\n… preview truncated":s;}
 static SortedMap<String,String>values(File f,String mode)throws Exception{
  SortedMap<String,String>map=new TreeMap<>();
  if(mode.equals("apk")){map.put("[Archive bytes]",FileOps.sha256(f));try(ZipFile z=new ZipFile(f)){Enumeration<? extends ZipEntry>es=z.entries();long total=0;while(es.hasMoreElements()){ZipEntry e=es.nextElement();if(e.isDirectory())continue;if(map.size()>=100000)throw new IOException("Too many entries");java.security.MessageDigest md=java.security.MessageDigest.getInstance("SHA-256");long len=0;try(InputStream in=z.getInputStream(e)){byte[]b=new byte[32768];int n;while((n=in.read(b))!=-1){total+=n;len+=n;if(total>FileOps.MAX_EXTRACT)throw new IOException("Comparison exceeds 1 GB");md.update(b,0,n);}}StringBuilder hash=new StringBuilder();for(byte b:md.digest())hash.append(String.format("%02x",b&255));map.put(e.getName(),len+" bytes\nSHA-256: "+hash);}}}
  else if(mode.equals("dex")){
   List<byte[]>inputs=new ArrayList<>();if(f.getName().endsWith(".dex"))inputs.add(FileOps.read(f,256L*1024*1024));else try(ZipFile z=new ZipFile(f)){Enumeration<? extends ZipEntry>es=z.entries();long total=0;while(es.hasMoreElements()){ZipEntry e=es.nextElement();if(e.getName().matches("classes[0-9]*\\.dex")){byte[]bytes=FileOps.bytes(z.getInputStream(e),256L*1024*1024-total);total+=bytes.length;inputs.add(bytes);}}}
   if(inputs.isEmpty())throw new IOException("No DEX files found");for(byte[]bytes:inputs){DexBackedDexFile d=new DexBackedDexFile(Opcodes.getDefault(),bytes);for(ClassDef c:d.getClasses()){StringWriter w=new StringWriter();new ClassDefinition(new BaksmaliOptions(),c).writeTo(new BaksmaliWriter(w));map.put(c.getType(),w.toString());}}
  }else{
   byte[]bytes;if(f.getName().endsWith(".apk"))bytes=FileOps.zipEntry(f,mode.equals("arsc")?"resources.arsc":"AndroidManifest.xml",32L*1024*1024);else bytes=FileOps.read(f,32L*1024*1024);
   if(mode.equals("arsc")){resourceChunks(bytes,0,bytes.length,"Resource",map);List<String>ss=Axml.resourceStrings(bytes);for(int i=0;i<ss.size();i++)map.put(String.format(Locale.ROOT,"String %08d",i),ss.get(i));}
   else{String xml=Axml.isBinary(bytes)?new Axml().decode(bytes):new String(bytes,StandardCharsets.UTF_8);String[]lines=xml.split("\n",-1);for(int i=0;i<lines.length;i++)map.put(String.format(Locale.ROOT,"Line %08d",i+1),lines[i]);}
  }return map;
 }
}
