package david.manager;

import java.util.*;
import org.json.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Cross references from parsed DEX instructions, never a substring search over Java. */
public final class DexQueries {
 private DexQueries() {}
 static String method(MethodReference m){StringBuilder b=new StringBuilder(m.getDefiningClass()+"->"+m.getName()+"(");for(CharSequence p:m.getParameterTypes())b.append(p);return b.append(')').append(m.getReturnType()).toString();}
 static String field(FieldReference f){return f.getDefiningClass()+"->"+f.getName()+":"+f.getType();}
 static String ref(Reference r){if(r instanceof MethodReference)return method((MethodReference)r);if(r instanceof FieldReference)return field((FieldReference)r);if(r instanceof TypeReference)return ((TypeReference)r).getType();if(r instanceof StringReference)return ((StringReference)r).getString();return r.toString();}
 static boolean typeMatches(String actual,String target){return actual.equals(target)||actual.replaceFirst("^\\[+","").equals(target);}
 static boolean uses(Reference r,String target,String kind){
  if(!kind.equals("class"))return ref(r).equals(target);
  if(r instanceof TypeReference)return typeMatches(((TypeReference)r).getType(),target);
  if(r instanceof FieldReference){FieldReference f=(FieldReference)r;return f.getDefiningClass().equals(target)||typeMatches(f.getType(),target);}
  if(r instanceof MethodReference){MethodReference m=(MethodReference)r;if(m.getDefiningClass().equals(target)||typeMatches(m.getReturnType(),target))return true;for(CharSequence p:m.getParameterTypes())if(typeMatches(p.toString(),target))return true;}
  return false;
 }
 static boolean childOf(String type,String parent,Map<String,ClassDef>classes,Set<String>seen){
  if(!seen.add(type))return false;ClassDef c=classes.get(type);if(c==null)return false;
  List<String>ps=new ArrayList<>(c.getInterfaces());if(c.getSuperclass()!=null)ps.add(c.getSuperclass());
  for(String p:ps)if(p.equals(parent)||childOf(p,parent,classes,seen))return true;return false;
 }
 public static JSONObject query(Map<String,ClassDef>classes,JSONObject a)throws Exception{
  String op=a.optString("op","usages"),kind=a.getString("kind"),target=a.getString("signature"),owner=a.optString("owner",target);
  JSONArray rows=new JSONArray();Set<String>seen=new HashSet<>();boolean truncated=false;
  outer:for(ClassDef c:classes.values()){
   if(op.equals("subclasses")){if(childOf(c.getType(),owner,classes,new HashSet<>()))add(rows,seen,c.getType(),"",c.getType(),"Subclass");}
   else if(op.equals("overrides")){
    if(!childOf(c.getType(),owner,classes,new HashSet<>()))continue;String tail=target.substring(target.indexOf("->")+2);
    for(Method m:c.getMethods())if((m.getAccessFlags()&(2|8))==0&&method(m).endsWith("->"+tail))add(rows,seen,c.getType(),method(m),method(m),"Override");
   }else{
    if(kind.equals("class")){
     if(typeMatches(String.valueOf(c.getSuperclass()),target)||c.getInterfaces().contains(target))add(rows,seen,c.getType(),"",target,"Parent/interface");
     for(Field f:c.getFields())if(typeMatches(f.getType(),target))add(rows,seen,c.getType(),"",field(f),"Field type");
    }
    for(Method m:c.getMethods()){
     String ms=method(m);
     if(kind.equals("class")){boolean sig=typeMatches(m.getReturnType(),target);for(CharSequence p:m.getParameterTypes())sig|=typeMatches(p.toString(),target);if(sig)add(rows,seen,c.getType(),ms,ms,"Method type");}
     MethodImplementation impl=m.getImplementation();if(impl==null)continue;
     for(Instruction ins:impl.getInstructions()){
      if(ins instanceof ReferenceInstruction&&uses(((ReferenceInstruction)ins).getReference(),target,kind))add(rows,seen,c.getType(),ms,ref(((ReferenceInstruction)ins).getReference()),"Instruction");
      if(ins instanceof DualReferenceInstruction&&uses(((DualReferenceInstruction)ins).getReference2(),target,kind))add(rows,seen,c.getType(),ms,ref(((DualReferenceInstruction)ins).getReference2()),"Instruction");
      if(rows.length()>=1000){truncated=true;break outer;}
     }
    }
   }
   if(rows.length()>=1000){truncated=true;break;}
  }
  return new JSONObject().put("rows",rows).put("truncated",truncated).put("scope","Selected DEX files; instructions and type declarations");
 }
 static void add(JSONArray out,Set<String>seen,String type,String method,String needle,String reason)throws Exception{String key=type+"|"+method+"|"+needle;if(seen.add(key))out.put(new JSONObject().put("class",type).put("method",method).put("needle",needle).put("reason",reason));}
}
