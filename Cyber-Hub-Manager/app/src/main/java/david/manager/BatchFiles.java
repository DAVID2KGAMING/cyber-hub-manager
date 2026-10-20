package david.manager;
import java.io.*;import java.nio.file.*;import java.util.*;import org.json.*;
final class BatchFiles {
 static JSONArray rename(JSONArray plans)throws Exception{
  List<File>src=new ArrayList<>(),dst=new ArrayList<>(),tmp=new ArrayList<>();Set<String>sources=new HashSet<>(),targets=new HashSet<>();
  for(int i=0;i<plans.length();i++){JSONObject p=plans.getJSONObject(i);File s=new File(p.getString("path")).getCanonicalFile(),d=FileOps.child(s.getParentFile(),p.getString("name"));if(!s.exists()||!sources.add(s.getPath())||!targets.add(d.getCanonicalPath()))throw new IOException("Missing source or duplicate rename target");src.add(s);dst.add(d);}
  for(File d:dst)if(d.exists()&&!sources.contains(d.getCanonicalPath()))throw new IOException("Rename target exists: "+d.getName());
  int staged=0,moved=0;try{
   for(File s:src){File t=new File(s.getParentFile(),".rename-"+UUID.randomUUID());Files.move(s.toPath(),t.toPath());tmp.add(t);staged++;}
   for(int i=0;i<src.size();i++){Files.move(tmp.get(i).toPath(),dst.get(i).toPath());moved++;}
  }catch(Exception e){try{for(int i=moved-1;i>=0;i--)Files.move(dst.get(i).toPath(),tmp.get(i).toPath());for(int i=staged-1;i>=0;i--)Files.move(tmp.get(i).toPath(),src.get(i).toPath());}catch(Exception rollback){e.addSuppressed(rollback);}throw e;}
  JSONArray out=new JSONArray();for(File f:dst)out.put(f.getPath());return out;
 }
 static JSONArray transfer(List<File>sources,List<String>names,File folder,boolean move)throws Exception{
  if(!folder.isDirectory())throw new IOException("Destination is not a directory");List<File>targets=new ArrayList<>();Set<String>seen=new HashSet<>();
  for(int i=0;i<sources.size();i++){File d=FileOps.child(folder,names.get(i)),s=sources.get(i);if(d.exists()||!seen.add(d.getCanonicalPath()))throw new IOException("Destination exists: "+d.getName());if(d.getCanonicalFile().toPath().startsWith(s.getCanonicalFile().toPath()))throw new IOException("Destination is inside a source");targets.add(d);}
  File stage=new File(folder,".transfer-"+UUID.randomUUID());if(!stage.mkdir())throw new IOException("Cannot stage transfer");List<File>published=new ArrayList<>();
  try{for(int i=0;i<sources.size();i++)FileOps.copyTree(sources.get(i),new File(stage,names.get(i)));for(int i=0;i<targets.size();i++){Files.move(new File(stage,names.get(i)).toPath(),targets.get(i).toPath());published.add(targets.get(i));}}
  catch(Exception e){for(File f:published)FileOps.deleteTree(f);throw e;}finally{FileOps.deleteTree(stage);}
  // Only remove sources after every destination has been published.
  if(move)for(File f:sources)FileOps.deleteTree(f);JSONArray out=new JSONArray();for(File f:targets)out.put(f.getPath());return out;
 }
}
