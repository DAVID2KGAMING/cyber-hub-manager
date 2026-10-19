package david.manager;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import org.eclipse.jdt.core.compiler.batch.BatchCompiler;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.value.*;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.DexFileFactory;
import org.objectweb.asm.*;

/** Compiles edited Java against API and DEX-derived signatures. Stub bytecode
 * is NEVER emitted into the APK. Only classes produced from the edited source
 * are passed to dx, validated, and handed to DexEngine's transaction. */
public final class JavaEditCompiler {
 private JavaEditCompiler() {}
 static final int MAX_SOURCE=2*1024*1024;
 public static Collection<? extends ClassDef> compile(String type,String text,
   Map<String,ClassDef> project,File platform,File session)throws Exception {
  if(text.length()>MAX_SOURCE)throw new IOException("Java source exceeds 2 MB");
  if(!platform.isFile())throw new IOException("Compiler API library is missing");
  File work=new File(session,"java-"+UUID.randomUUID());if(!work.mkdirs())throw new IOException("Cannot create compiler workspace");
  try {
   String binary=internal(type),simple=binary.substring(binary.lastIndexOf('/')+1);
   if(simple.indexOf('$')>=0)throw new IOException("Open the enclosing Java class to compile nested classes together");
   File source=new File(work,simple+".java"),output=new File(work,"classes");output.mkdirs();
   FileOps.writeAtomic(source,text.getBytes(StandardCharsets.UTF_8),false);
   File stubs=new File(work,"project-api.jar");writeStubs(stubs,project);
   StringWriter log=new StringWriter();PrintWriter messages=new PrintWriter(log);
   boolean ok=BatchCompiler.compile(new String[]{"-1.8","-proc:none","-g","-nowarn","-encoding","UTF-8","-maxProblems","30","-bootclasspath",platform.getPath(),"-classpath",stubs.getPath(),"-d",output.getPath(),source.getPath()},messages,messages,null);
   messages.flush();
   if(!ok)throw new IOException("Java compilation failed. Your edits are still open.\n"+cleanLog(log.toString(),work));
   File classJar=new File(work,"compiled.jar");List<File>compiled=new ArrayList<>();collectClasses(output,compiled);
   if(compiled.isEmpty())throw new IOException("The compiler did not emit any classes");
   boolean main=false;
   try(ZipOutputStream zip=new ZipOutputStream(new FileOutputStream(classJar))){
    for(File f:compiled){String name=output.toPath().relativize(f.toPath()).toString().replace(File.separatorChar,'/'),descriptor="L"+name.substring(0,name.length()-6)+";";
     if(!descriptor.equals(type)&&!descriptor.startsWith(type.substring(0,type.length()-1)+"$"))throw new IOException("Keep package and class name unchanged. Extra top-level class: "+descriptor);
     main|=descriptor.equals(type);byte[] bytecode=FileOps.read(f,8L*1024*1024);validateBytecode(bytecode);zip.putNextEntry(new ZipEntry(name));zip.write(bytecode);zip.closeEntry();
    }
   }
   if(!main)throw new IOException("Keep the original class declaration: "+binary.replace('/','.'));
   ByteArrayOutputStream dxLog=new ByteArrayOutputStream();PrintStream dxOut=new PrintStream(dxLog,true,"UTF-8");
   com.android.dx.command.dexer.DxContext context=new com.android.dx.command.dexer.DxContext(dxOut,dxOut);
   File dex=new File(work,"compiled.dex");
   int result=com.android.dx.command.dexer.CyberCompiler.compile(context,classJar.getPath(),dex.getPath());
   if(result!=0||!dex.isFile())throw new IOException("DEX compilation failed. Your edits are still open.\n"+dxLog.toString("UTF-8"));
   DexBackedDexFile parsed=DexFileFactory.loadDexFile(dex,org.jf.dexlib2.Opcodes.getDefault());
   // Immutable copies detach the replacement from the temporary compiler files.
   List<ClassDef> replacements=new ArrayList<>();for(ClassDef c:parsed.getClasses())replacements.add(org.jf.dexlib2.immutable.ImmutableClassDef.of(c));
   return replacements;
  } finally {FileOps.deleteTree(work);}
 }
 static String cleanLog(String log,File dir){String clean=log.replace(dir.getAbsolutePath()+File.separator,"");return clean.length()>24000?clean.substring(0,24000):clean;}
 static void validateBytecode(byte[] bytes)throws IOException {
  final boolean[] dynamic={false};new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9){
   @Override public MethodVisitor visitMethod(int access,String name,String descriptor,String signature,String[] exceptions){return new MethodVisitor(Opcodes.ASM9){@Override public void visitInvokeDynamicInsn(String name,String descriptor,Handle handle,Object... arguments){dynamic[0]=true;}};}
  },ClassReader.SKIP_DEBUG|ClassReader.SKIP_FRAMES);
  if(dynamic[0])throw new IOException("This Java source needs bytecode desugaring. Use an anonymous class instead of a lambda/method reference, or edit Smali. Existing DEX is unchanged.");
 }
 static void collectClasses(File dir,List<File>out)throws IOException {File[]fs=dir.listFiles();if(fs==null)throw new IOException("Cannot read compiler output");for(File f:fs)if(f.isDirectory())collectClasses(f,out);else if(f.getName().endsWith(".class"))out.add(f);}
 static String internal(String type){return type.charAt(0)=='L'?type.substring(1,type.length()-1):type;}
 static String signature(Set<? extends Annotation> annotations){for(Annotation a:annotations)if(a.getType().equals("Ldalvik/annotation/Signature;"))for(AnnotationElement e:a.getElements())if(e.getValue() instanceof ArrayEncodedValue){StringBuilder b=new StringBuilder();for(EncodedValue v:((ArrayEncodedValue)e.getValue()).getValue())if(v instanceof StringEncodedValue)b.append(((StringEncodedValue)v).getValue());return b.toString();}return null;}
 static String[] exceptions(Set<? extends Annotation> annotations){for(Annotation a:annotations)if(a.getType().equals("Ldalvik/annotation/Throws;"))for(AnnotationElement e:a.getElements())if(e.getValue() instanceof ArrayEncodedValue){List<String>out=new ArrayList<>();for(EncodedValue v:((ArrayEncodedValue)e.getValue()).getValue())if(v instanceof TypeEncodedValue)out.add(internal(((TypeEncodedValue)v).getValue()));return out.toArray(new String[0]);}return null;}
 static Object constant(EncodedValue v){if(v instanceof StringEncodedValue)return ((StringEncodedValue)v).getValue();if(v instanceof IntEncodedValue)return ((IntEncodedValue)v).getValue();if(v instanceof BooleanEncodedValue)return ((BooleanEncodedValue)v).getValue()?1:0;if(v instanceof ByteEncodedValue)return (int)((ByteEncodedValue)v).getValue();if(v instanceof ShortEncodedValue)return (int)((ShortEncodedValue)v).getValue();if(v instanceof CharEncodedValue)return (int)((CharEncodedValue)v).getValue();if(v instanceof LongEncodedValue)return ((LongEncodedValue)v).getValue();if(v instanceof FloatEncodedValue)return ((FloatEncodedValue)v).getValue();if(v instanceof DoubleEncodedValue)return ((DoubleEncodedValue)v).getValue();return null;}
 static String methodDescriptor(Method m){StringBuilder s=new StringBuilder("(");for(CharSequence p:m.getParameterTypes())s.append(p);return s.append(')').append(m.getReturnType()).toString();}
 static final class Inner {String name,outer,simple;int flags;Inner(ClassDef c){name=internal(c.getType());int dollar=name.lastIndexOf('$');if(dollar<0)return;outer=name.substring(0,dollar);simple=name.substring(dollar+1);flags=c.getAccessFlags()&0xffff;
  for(Annotation a:c.getAnnotations())if(a.getType().equals("Ldalvik/annotation/InnerClass;"))for(AnnotationElement e:a.getElements()){if(e.getName().equals("name"))simple=e.getValue() instanceof StringEncodedValue?((StringEncodedValue)e.getValue()).getValue():null;if(e.getName().equals("accessFlags")&&e.getValue() instanceof IntEncodedValue)flags=((IntEncodedValue)e.getValue()).getValue()&0xffff;}
 }}
 static void writeStubs(File file,Map<String,ClassDef>classes)throws IOException {
  Map<String,List<Inner>>children=new HashMap<>();Map<String,Inner>inners=new HashMap<>();for(ClassDef c:classes.values()){Inner in=new Inner(c);if(in.outer!=null){inners.put(in.name,in);children.computeIfAbsent(in.outer,k->new ArrayList<>()).add(in);}}
  try(ZipOutputStream out=new ZipOutputStream(new FileOutputStream(file))){
   for(ClassDef c:classes.values()){
    String name=internal(c.getType());if(name.startsWith("java/")||name.startsWith("javax/"))continue;
    ClassWriter writer=new ClassWriter(0);String parent=c.getSuperclass()==null?null:internal(c.getSuperclass());String[]interfaces=c.getInterfaces().stream().map(JavaEditCompiler::internal).toArray(String[]::new);
    writer.visit(Opcodes.V1_8,c.getAccessFlags()&0xffff,name,signature(c.getAnnotations()),parent,interfaces);
    Inner self=inners.get(name);if(self!=null)writer.visitInnerClass(self.name,self.outer,self.simple,self.flags);
    for(Inner child:children.getOrDefault(name,Collections.emptyList()))writer.visitInnerClass(child.name,child.outer,child.simple,child.flags);
    for(Field f:c.getFields())writer.visitField(f.getAccessFlags()&0xffff,f.getName(),f.getType(),signature(f.getAnnotations()),constant(f.getInitialValue())).visitEnd();
    for(Method m:c.getMethods()){
     if(m.getName().equals("<clinit>"))continue;int flags=m.getAccessFlags()&0xffff;String desc=methodDescriptor(m);
     MethodVisitor method=writer.visitMethod(flags,m.getName(),desc,signature(m.getAnnotations()),exceptions(m.getAnnotations()));
     if((flags&(Opcodes.ACC_ABSTRACT|Opcodes.ACC_NATIVE))==0){method.visitCode();method.visitInsn(Opcodes.ACONST_NULL);method.visitInsn(Opcodes.ATHROW);int locals=(flags&Opcodes.ACC_STATIC)==0?1:0;for(Type t:Type.getArgumentTypes(desc))locals+=t.getSize();method.visitMaxs(1,locals);}
     method.visitEnd();
    }
    writer.visitEnd();out.putNextEntry(new ZipEntry(name+".class"));out.write(writer.toByteArray());out.closeEntry();
   }
  }
 }
}
