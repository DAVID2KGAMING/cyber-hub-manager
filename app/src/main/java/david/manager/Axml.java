package david.manager;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

/** Android binary XML reader/writer. Resource IDs and existing typed values survive edits. */
public final class Axml {
    private static final String ANDROID="http://schemas.android.com/apk/res/android";
    public final Map<String,Integer> resourceIds=new HashMap<>();
    private final Map<String,String> nameAliases=new HashMap<>();
    private String safeName(String name){if(name.matches("[A-Za-z_][A-Za-z0-9_.-]*"))return name;StringBuilder b=new StringBuilder("chx_");for(byte v:name.getBytes(StandardCharsets.UTF_8))b.append(String.format("%02x",v&255));String alias=b.toString();nameAliases.put(alias,name);return alias;}
    private String nodeName(Node node){String n=node.getLocalName()==null?node.getNodeName():node.getLocalName();return nameAliases.getOrDefault(n,n);}
    private final Map<String,Typed> typedValues=new HashMap<>();
    private final Map<String,Integer> attributeTypes=new HashMap<>();
    private static class Typed { int type,data; Typed(int t,int d){type=t;data=d;} }
    public static boolean isBinary(byte[] b){return b.length>=8 && (b[0]&255)==3 && b[1]==0 && b[2]==8;}
    static int i(byte[] b,int p){if(p<0 || p+4>b.length)throw new IllegalArgumentException("Truncated Android resource");return (b[p]&255)|(b[p+1]&255)<<8|(b[p+2]&255)<<16|b[p+3]<<24;}
    static int u(byte[] b,int p){if(p<0 || p+2>b.length)throw new IllegalArgumentException("Truncated Android resource");return (b[p]&255)|(b[p+1]&255)<<8;}
    public static List<String> strings(byte[] b,int base){
        int count=i(b,base+8), flags=i(b,base+16), start=i(b,base+20), header=u(b,base+2), size=i(b,base+4);
        if(count<0 || count>1000000 || base+size>b.length || (long)base+header+(long)count*4>b.length)throw new IllegalArgumentException("Invalid string pool");
        List<String> ss=new ArrayList<>();
        for(int n=0;n<count;n++){
            int p=base+start+i(b,base+header+n*4),length;
            if((flags&256)!=0){int a=b[p++]&255;if((a&128)!=0)p++;length=b[p++]&255;if((length&128)!=0)length=((length&127)<<8)|(b[p++]&255);if(p+length>b.length)throw new IllegalArgumentException("Truncated string");ss.add(new String(b,p,length,StandardCharsets.UTF_8));}
            else {length=u(b,p);p+=2;if((length&32768)!=0){length=((length&32767)<<16)|u(b,p);p+=2;}if(length<0 || (long)p+length*2L>b.length)throw new IllegalArgumentException("Truncated string");ss.add(new String(b,p,length*2,StandardCharsets.UTF_16LE));}
        }return ss;
    }
    public static List<String> resourceStrings(byte[] b){int p=u(b,2);while(p+8<=b.length){int size=i(b,p+4);if(size<8 || (long)p+size>b.length)break;if(u(b,p)==1)return strings(b,p);p+=size;}return Collections.emptyList();}
    private static String s(List<String> ss,int n){return n<0?"":ss.get(n);}
    private static String esc(String s){return s.replace("&","&amp;").replace("<","&lt;").replace("\"","&quot;").replace("\n","&#10;").replace("\r","&#13;");}
    private static String value(int t,int d,List<String> ss){
        switch(t){case 3:return s(ss,d);case 1:return String.format("@0x%08x",d);case 2:return String.format("?0x%08x",d);case 18:return d==0?"false":"true";case 16:return Integer.toString(d);case 17:return String.format("0x%08x",d);case 4:return Float.toString(Float.intBitsToFloat(d));case 0:return "@null";default:if(t>=28&&t<=31)return String.format("#%08x",d);return String.format("@typed:%02x:%08x",t,d);}
    }
    public String decode(byte[] b){
        if(!isBinary(b))return new String(b,StandardCharsets.UTF_8);
        List<String> ss=Collections.emptyList();int[] ids=new int[0];Map<String,String> ns=new LinkedHashMap<>();
        StringBuilder out=new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");int depth=0;boolean root=true;
        for(int p=8;p+8<=b.length;){int type=u(b,p),size=i(b,p+4);if(size<8 || (long)p+size>b.length)throw new IllegalArgumentException("Invalid binary XML chunk");
            if(type==1)ss=strings(b,p);
            else if(type==0x180){ids=new int[(size-8)/4];for(int n=0;n<ids.length;n++)ids[n]=i(b,p+8+n*4);}
            else if(type==0x100){ns.put(s(ss,i(b,p+20)),s(ss,i(b,p+16)));}
            else if(type==0x102){
                String uri=s(ss,i(b,p+16)),name=s(ss,i(b,p+20));indent(out,depth);out.append('<').append(qname(uri,name,ns));
                if(root){for(Map.Entry<String,String> e:ns.entrySet())out.append(" xmlns").append(e.getValue().isEmpty()?"":":"+e.getValue()).append("=\"").append(esc(e.getKey())).append('"');root=false;}
                int start=u(b,p+24),stride=u(b,p+26),count=u(b,p+28);if(stride<20)throw new IllegalArgumentException("Invalid attributes");
                for(int n=0;n<count;n++){int a=p+16+start+n*stride;String au=s(ss,i(b,a)),an=s(ss,i(b,a+4));int raw=i(b,a+8),t=b[a+15]&255,d=i(b,a+16);String v=raw>=0?s(ss,raw):value(t,d,ss);int ix=i(b,a+4);if(ix<ids.length&&ids[ix]!=0)resourceIds.put(au+"|"+an,ids[ix]);typedValues.put(au+"|"+an+"|"+v,new Typed(t,d));attributeTypes.put(au+"|"+an,t);out.append("\n");indent(out,depth+1);out.append(qname(au,an,ns)).append("=\"").append(esc(v)).append('"');}
                out.append(">\n");depth++;
            }else if(type==0x103){depth--;indent(out,depth);out.append("</").append(qname(s(ss,i(b,p+16)),s(ss,i(b,p+20)),ns)).append(">\n");}
            else if(type==0x104){indent(out,depth);out.append(esc(s(ss,i(b,p+16)))).append('\n');}
            p+=size;
        }return out.toString();
    }
    private String qname(String uri,String name,Map<String,String>ns){String p=ns.get(uri);String n=safeName(name);return p==null||p.isEmpty()?n:p+":"+n;}
    private static void indent(StringBuilder b,int n){for(int j=0;j<n;j++)b.append("    ");}
    private final List<String> pool=new ArrayList<>();private final Map<String,Integer> indices=new HashMap<>();
    private int str(String s){if(s==null)return -1;Integer n=indices.get(s);if(n!=null)return n;int v=pool.size();pool.add(s);indices.put(s,v);return v;}
    private static class LE extends ByteArrayOutputStream {void h(int v){write(v);write(v>>>8);}void w(int v){h(v);h(v>>>16);}void data(byte[] b){write(b,0,b.length);} }
    private static byte[] chunk(int type,int header,byte[] payload){LE b=new LE();b.h(type);b.h(header);b.w(payload.length+8);b.data(payload);return b.toByteArray();}
    private byte[] stringPool(){LE data=new LE(),offsets=new LE();for(String s:pool){offsets.w(data.size());int l=s.length();if(l>32767){data.h((l>>>16)|32768);data.h(l&65535);}else data.h(l);data.data(s.getBytes(StandardCharsets.UTF_16LE));data.h(0);}while(data.size()%4!=0)data.write(0);LE b=new LE();b.w(pool.size());b.w(0);b.w(0);b.w(28+pool.size()*4);b.w(0);b.data(offsets.toByteArray());b.data(data.toByteArray());return chunk(1,28,b.toByteArray());}
    private byte[] node(int type,LE body){LE p=new LE();p.w(1);p.w(-1);p.data(body.toByteArray());return chunk(type,16,p.toByteArray());}
    private Typed typed(Attr a){String v=a.getValue(),uri=a.getNamespaceURI()==null?"":a.getNamespaceURI();Typed t=typedValues.get(uri+"|"+nodeName(a)+"|"+v);if(t!=null)return t.type==3?new Typed(3,str(v)):t;
        if(v.equals("@null"))return new Typed(0,0);
        if(v.matches("[@?]0x[0-9a-fA-F]{1,8}"))return new Typed(v.charAt(0)=='@'?1:2,(int)Long.parseLong(v.substring(3),16));
        if(v.startsWith("@")||v.startsWith("?"))throw new IllegalArgumentException("Use numeric resource IDs, e.g. @0x7f010001, for "+a.getName());
        Integer hint=attributeTypes.get(uri+"|"+nodeName(a));
        if(hint!=null && (hint==3 || hint==1 || hint==2))return new Typed(3,str(v));
        if(v.equals("true")||v.equals("false"))return new Typed(18,v.equals("true")?-1:0);
        try {if(v.matches("-?[0-9]+"))return new Typed(16,Integer.parseInt(v));if(v.matches("0x[0-9a-fA-F]+"))return new Typed(17,(int)Long.parseLong(v.substring(2),16));if(v.matches("#[0-9a-fA-F]{8}"))return new Typed(28,(int)Long.parseLong(v.substring(1),16));}catch(NumberFormatException ignored){}
        return new Typed(3,str(v));
    }
    private int attrId(Attr a){String uri=a.getNamespaceURI()==null?"":a.getNamespaceURI(),local=nodeName(a);Integer id=resourceIds.get(uri+"|"+local);if(id!=null)return id;
        if(uri.equals(ANDROID)){try {int found=Class.forName("android.R$attr").getField(local).getInt(null);resourceIds.put(uri+"|"+local,found);return found;}catch(Exception ignored){throw new IllegalArgumentException("Unknown Android attribute: "+local);}}return 0;}
    private void gather(Element e,Map<String,String>ns){str(e.getNamespaceURI());str(nodeName(e));NamedNodeMap at=e.getAttributes();for(int n=0;n<at.getLength();n++){Attr a=(Attr)at.item(n);if(a.getName().equals("xmlns")||a.getName().startsWith("xmlns:")){ns.put(a.getValue(),a.getName().equals("xmlns")?"":a.getLocalName());str(a.getValue());str(ns.get(a.getValue()));}else{str(a.getNamespaceURI());str(nodeName(a));str(a.getValue());attrId(a);typed(a);}}for(Node c=e.getFirstChild();c!=null;c=c.getNextSibling())if(c instanceof Element)gather((Element)c,ns);else if(c.getNodeType()==Node.TEXT_NODE&&!c.getNodeValue().trim().isEmpty())str(c.getNodeValue());}
    private void element(Element e,LE out){List<Attr>attrs=new ArrayList<>();NamedNodeMap map=e.getAttributes();for(int n=0;n<map.getLength();n++){Attr a=(Attr)map.item(n);if(!a.getName().equals("xmlns")&&!a.getName().startsWith("xmlns:"))attrs.add(a);}attrs.sort((a,b)->Integer.compareUnsigned(attrId(a),attrId(b)));
        LE body=new LE();body.w(str(e.getNamespaceURI()));body.w(str(nodeName(e)));body.h(20);body.h(20);body.h(attrs.size());int id=0,cl=0,st=0;for(int n=0;n<attrs.size();n++){String name=attrs.get(n).getName();if(name.equals("android:id"))id=n+1;if(name.equals("class"))cl=n+1;if(name.equals("style"))st=n+1;}body.h(id);body.h(cl);body.h(st);
        for(Attr a:attrs){Typed t=typed(a);body.w(str(a.getNamespaceURI()));body.w(str(nodeName(a)));body.w(str(a.getValue()));body.h(8);body.write(0);body.write(t.type);body.w(t.data);}out.data(node(0x102,body));
        for(Node c=e.getFirstChild();c!=null;c=c.getNextSibling()){if(c instanceof Element)element((Element)c,out);else if(c.getNodeType()==Node.TEXT_NODE&&!c.getNodeValue().trim().isEmpty()){LE text=new LE();text.w(str(c.getNodeValue()));text.h(8);text.write(0);text.write(3);text.w(str(c.getNodeValue()));out.data(node(0x104,text));}}
        LE end=new LE();end.w(str(e.getNamespaceURI()));end.w(str(nodeName(e)));out.data(node(0x103,end));
    }
    public byte[] encode(String xml)throws Exception {
        if(xml.contains("<!DOCTYPE")||xml.contains("<!ENTITY"))throw new IOException("XML document types/entities are not supported");
        DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setNamespaceAware(true);f.setExpandEntityReferences(false);Document d=f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));pool.clear();indices.clear();Map<String,String>ns=new LinkedHashMap<>();gather(d.getDocumentElement(),ns);
        LE content=new LE();for(Map.Entry<String,String>e:ns.entrySet()){LE n=new LE();n.w(str(e.getValue()));n.w(str(e.getKey()));content.data(node(0x100,n));}element(d.getDocumentElement(),content);
        List<Map.Entry<String,String>> reversed=new ArrayList<>(ns.entrySet());Collections.reverse(reversed);for(Map.Entry<String,String>e:reversed){LE n=new LE();n.w(str(e.getValue()));n.w(str(e.getKey()));content.data(node(0x101,n));}
        LE ids=new LE();int[] res=new int[pool.size()];for(Map.Entry<String,Integer>e:resourceIds.entrySet()){String local=e.getKey().substring(e.getKey().indexOf('|')+1);Integer ix=indices.get(local);if(ix!=null)res[ix]=e.getValue();}for(int v:res)ids.w(v);
        LE all=new LE();all.data(stringPool());all.data(chunk(0x180,8,ids.toByteArray()));all.data(content.toByteArray());return chunk(3,8,all.toByteArray());
    }
}
