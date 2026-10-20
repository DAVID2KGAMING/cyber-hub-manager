package david.manager;
import java.io.File;
import java.util.*;
import org.json.*;
import org.jf.dexlib2.immutable.ImmutableClassDef;
public final class DexTreeSmokeTest {
 public static void main(String[] args)throws Exception{
  DexEngine engine=new DexEngine(new File(args[0],"tree-only"));
  for(String type:Arrays.asList("Landroid/net/Socket;","Lcom/android/internal/http/multipart/Part;","Lcom/cyberalpha/stringtobyte/MainActivity;","Lcom/cyberalpha/stringtobyte/MainActivity$1;","Lorg/apache/Utils;"))engine.classes.put(type,new ImmutableClassDef(type,1,"Ljava/lang/Object;",Collections.emptyList(),null,Collections.emptySet(),Collections.emptyList(),Collections.emptyList()));
  JSONArray root=engine.tree("");
  if(root.length()!=3||!root.getJSONObject(0).getString("name").equals("android.net")||!root.getJSONObject(1).getString("name").equals("com"))throw new AssertionError("Root package compaction");
  JSONArray com=engine.tree("com/");
  if(com.length()!=2||!com.getJSONObject(0).getString("name").equals("android.internal.http.multipart")||!com.getJSONObject(1).getString("prefix").equals("com/cyberalpha/stringtobyte/"))throw new AssertionError("Branch packages");
  if(engine.tree("com/cyberalpha/stringtobyte/").length()!=2)throw new AssertionError("Leaf classes missing");
  String parent="Lcom/cyberalpha/Parent;";engine.classes.put(parent,new ImmutableClassDef(parent,1,"Ljava/lang/Object;",Collections.emptyList(),null,Collections.emptySet(),Collections.emptyList(),Collections.emptyList()));
  if(!engine.tree("com/").getJSONObject(1).getString("name").equals("cyberalpha"))throw new AssertionError("Compaction skipped a package with a class");
  System.out.println("PASS DEX compact root and nested package names");
  System.out.println("PASS DEX compaction preserves branches and parent classes");
  engine.close();
 }
}
