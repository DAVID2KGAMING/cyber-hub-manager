package david.manager;

import com.android.apksig.ApkVerifier;
import com.google.protobuf.CodedInputStream;
import com.reandroid.apk.ApkModule;
import com.reandroid.apk.AndroidManifestBlockMerger;
import com.reandroid.archive.ZipEntryMap;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.json.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

/** Offline resource-aware APKS conversion. All work precedes publication of a new file. */
public final class ApksConverter {
    static final long MAX_APK=256L*1024*1024, MAX_TOTAL=1024L*1024*1024;
    static final int MAX_APKS=1024, MAX_ENTRIES=100000;
    public interface Progress { void stage(String message); }
    private static final Progress SILENT=message->{};
    private static final class Plan {
        String id,label; final List<String> paths=new ArrayList<>();
        Plan(String id,String label){this.id=id;this.label=label;}
        JSONObject json()throws JSONException{return new JSONObject().put("id",id).put("label",label).put("count",paths.size()).put("entries",new JSONArray(paths));}
    }
    private static final class Catalog {
        final Map<String,ZipEntry> entries=new LinkedHashMap<>();
        final List<Plan> plans=new ArrayList<>(); final List<String> skipped=new ArrayList<>();
    }

    public static JSONObject inspect(File source)throws Exception {
        try(ZipFile zip=new ZipFile(source)){
            Catalog c=catalog(zip);JSONArray choices=new JSONArray();for(Plan p:c.plans)choices.put(p.json());
            return new JSONObject().put("choices",choices).put("skipped",new JSONArray(c.skipped))
                    .put("fingerprint",FileOps.sha256(source)).put("name",source.getName());
        }
    }

    public static JSONObject convert(File source,File destination,String choice,String fingerprint,
                                     File cache,InputStream signingKey,Progress progress)throws Exception {
        Progress p=progress==null?SILENT:progress;
        if(!source.isFile())throw new IOException("APKS file no longer exists");
        if(destination.exists())throw new IOException("Output already exists; choose another name");
        if(!destination.getName().toLowerCase(Locale.ROOT).endsWith(".apk"))throw new IOException("Output name must end in .apk");
        if(!destination.getParentFile().isDirectory())throw new IOException("Destination folder does not exist");
        p.stage("Checking APKS archive…");
        if(fingerprint==null||!fingerprint.equals(FileOps.sha256(source)))throw new IOException("APKS changed. Open Convert to APK again.");
        cache.mkdirs();File work=Files.createTempDirectory(cache.toPath(),"apks-").toFile();
        List<ApkModule> modules=new ArrayList<>();ApkModule merged=null;
        try(ZipFile zip=new ZipFile(source)){
            Catalog catalog=catalog(zip);Plan plan=null;
            for(Plan candidate:catalog.plans)if(candidate.id.equals(choice)){plan=candidate;break;}
            if(plan==null)throw new IOException("Select an available APK variant");
            long total=0;List<File> files=new ArrayList<>();
            for(int i=0;i<plan.paths.size();i++){
                ZipEntry entry=catalog.entries.get(plan.paths.get(i));
                if(entry==null||entry.isDirectory())throw new IOException("Missing APK: "+plan.paths.get(i));
                p.stage("Reading APK "+(i+1)+" of "+plan.paths.size()+"…");
                File file=new File(work,"module-"+i+".apk");
                try(InputStream in=zip.getInputStream(entry);OutputStream out=new FileOutputStream(file)){
                    total+=copyChecked(in,out,Math.min(MAX_APK,MAX_TOTAL-total),entry);
                }
                files.add(file);
            }
            if(!fingerprint.equals(FileOps.sha256(source)))throw new IOException("APKS changed during conversion; no output was saved");
            p.stage("Validating package, resources and classes…");
            validateEntries(files);
            ApkModule base=null;String packageName=null,version=null;Set<String> splits=new HashSet<>(),types=new HashSet<>();
            for(int i=0;i<files.size();i++){
                ApkModule module=ApkModule.loadApkFile(files.get(i),"module-"+i);modules.add(module);module.setLoadDefaultFramework(false);
                AndroidManifestBlock m=module.getAndroidManifest();
                if(m==null||m.getManifestElement()==null||m.getPackageName()==null)throw new IOException("APK has no readable Android manifest");
                String v=String.valueOf(m.getVersionCode())+":"+attribute(m.getManifestElement(),"versionCodeMajor");
                if(packageName==null){packageName=m.getPackageName();version=v;}
                if(!packageName.equals(m.getPackageName())||!version.equals(v))throw new IOException("APKs belong to different packages or versions");
                String split=m.getSplit();
                if(split==null||split.isEmpty()){if(base!=null)throw new IOException("Multiple base APKs found. Choose one bundletool variant or use a single split set.");base=module;}
                else if(!splits.add(split))throw new IOException("Duplicate split ID: "+split);
                addTypes(types,attribute(m.getManifestElement(),"splitTypes"));
            }
            if(base==null)throw new IOException("Missing base APK; configuration splits alone cannot become an APK");
            for(ApkModule module:modules){
                AndroidManifestBlock m=module.getAndroidManifest();ResXmlElement root=m.getManifestElement();
                String parent=attribute(root,"configForSplit");
                if(!parent.isEmpty()&&!parent.equals("base")&&!splits.contains(parent))throw new IOException("Missing feature split: "+parent);
                for(Iterator<ResXmlElement> it=root.getElements();it.hasNext();){ResXmlElement child=it.next();if("uses-split".equals(child.getName())){String name=attribute(child,"name");if(!name.equals("base")&&!splits.contains(name))throw new IOException("Missing required split: "+name);}}
                Set<String> required=new HashSet<>();addTypes(required,attribute(root,"requiredSplitTypes"));
                if(!types.containsAll(required))throw new IOException("Missing required split types: "+required);
            }
            File ready;boolean preserved=false;
            if(modules.size()==1){
                if("true".equals(attribute(base.getAndroidManifest().getApplicationElement(),"isSplitRequired"))||"true".equals(attribute(base.getAndroidManifest().getManifestElement(),"isSplitRequired")))throw new IOException("This base APK requires splits that are missing from the archive");
                ready=files.get(0);p.stage("Verifying standalone APK…");
                preserved=new ApkVerifier.Builder(ready).build().verify().isVerified();
            }else{
                p.stage("Merging resources, DEX and feature manifests…");
                merged=new ApkModule("merged",new ZipEntryMap());merged.setLoadDefaultFramework(false);merged.merge(base);
                AndroidManifestBlockMerger merger=new AndroidManifestBlockMerger().initializeBase(merged.getAndroidManifest());
                for(ApkModule module:modules)if(module!=base){merged.merge(module);merger.merge(module.getAndroidManifest());}
                merger.sanitize(merged);sanitize(merged.getAndroidManifest().getManifestElement());
                merged.setApkSignatureBlock(null);merged.refreshTable();merged.refreshManifest();
                File raw=new File(work,"merged-raw.apk");merged.writeApk(raw);
                p.stage("Aligning APK contents…");ready=new File(work,"merged-aligned.apk");FileOps.rewriteZip(raw,ready,Collections.emptyMap());
            }
            File signed=new File(work,"verified.apk");
            if(preserved)Files.copy(ready.toPath(),signed.toPath());
            else{p.stage("Signing APK (V1, V2, V3)…");ApkSigning.sign(ready,signed,signingKey);}
            p.stage("Verifying converted APK…");
            ApkVerifier.Result verification=new ApkVerifier.Builder(signed).build().verify();
            if(!verification.isVerified())throw new IOException("Output signature verification failed: "+verification.getErrors());
            try(ApkModule check=ApkModule.loadApkFile(signed)){
                check.setLoadDefaultFramework(false);AndroidManifestBlock m=check.getAndroidManifest();
                if(m==null||m.isSplit()||!packageName.equals(m.getPackageName()))throw new IOException("Merged APK manifest validation failed");
                if(check.hasTableBlock())check.getTableBlock().refresh();
            }
            // Copy to the destination filesystem first, then publish without replacing any existing file.
            p.stage("Saving APK…");File staging=File.createTempFile(".apks-output-",".tmp",destination.getParentFile());
            try{
                try(InputStream in=new FileInputStream(signed);FileOutputStream out=new FileOutputStream(staging)){FileOps.copy(in,out,MAX_TOTAL);out.getFD().sync();}
                String hash=FileOps.sha256(staging);if(!hash.equals(FileOps.sha256(signed)))throw new IOException("Output copy verification failed");
                Files.move(staging.toPath(),destination.toPath());
                return new JSONObject().put("path",destination.getPath()).put("package",packageName).put("size",destination.length())
                        .put("sha256",hash).put("verified",true).put("originalSignature",preserved).put("merged",modules.size()>1).put("apkCount",modules.size());
            }finally{staging.delete();}
        }finally{
            if(merged!=null)try{merged.close();}catch(IOException ignored){}
            for(ApkModule module:modules)try{module.close();}catch(IOException ignored){}
            try{FileOps.deleteTree(work);}catch(IOException ignored){/* OS cache eviction can reclaim a locked temp file. */}
        }
    }

    private static Catalog catalog(ZipFile zip)throws Exception {
        Catalog c=new Catalog();List<String> apks=new ArrayList<>();int count=0;
        for(Enumeration<? extends ZipEntry> e=zip.entries();e.hasMoreElements();){
            ZipEntry entry=e.nextElement();String name=entry.getName();validPath(name);
            if(++count>MAX_ENTRIES)throw new IOException("Archive contains too many entries");
            if(c.entries.put(name,entry)!=null)throw new IOException("Duplicate archive entry: "+name);
            if(entry.isDirectory())continue;
            String lower=name.toLowerCase(Locale.ROOT);
            if(lower.endsWith(".obb"))throw new IOException("This archive contains OBB data, which cannot be embedded in a single APK");
            if(lower.endsWith(".apk")){if(entry.getSize()<0||entry.getSize()>MAX_APK)throw new IOException("APK exceeds the 256 MB per-file conversion limit");apks.add(name);}
        }
        if(apks.isEmpty())throw new IOException("No APK files found inside this APKS archive");
        if(apks.size()>MAX_APKS)throw new IOException("Too many APKs in this bundle (maximum 1024)");
        ZipEntry toc=c.entries.get("toc.pb");
        if(toc==null){Plan plan=new Plan("split-set",apks.size()==1?"Single APK":"Base + "+(apks.size()-1)+" splits");plan.paths.addAll(apks);c.plans.add(plan);return c;}
        Proto result;try(InputStream in=zip.getInputStream(toc)){result=new Proto(FileOps.bytes(in,4*1024*1024));}
        if(result.has(3)||result.has(6))throw new IOException("Play Asset Delivery packs cannot be converted into a self-contained APK");
        int vi=0;
        for(byte[] bytes:result.values(1)){
            Proto variant=new Proto(bytes);String id="variant-"+(vi++);String label="Variant "+variant.number(3)+targetLabel(variant.first(1));
            Proto variantTarget=new Proto(variant.first(1));
            if(variantTarget.has(5)||variantTarget.has(6)){c.skipped.add(label+": unsupported texture or SDK-runtime targeting");continue;}
            Plan splits=new Plan(id,label+" · merge splits");List<Plan> standalone=new ArrayList<>();String unsupported=null;
            for(byte[] set:variant.values(2)){
                Proto apkSet=new Proto(set),metadata=new Proto(apkSet.first(1));
                if(metadata.number(3)!=0||metadata.has(8)||(metadata.number(7)>1)){unsupported="instant or SDK modules";break;}
                // Conditions requiring Play delivery cannot be faithfully represented by one ordinary APK.
                if(metadata.has(5)&&!new Proto(metadata.first(5)).empty()){unsupported="conditional feature delivery";break;}
                for(byte[] description:apkSet.values(2)){
                    Proto apk=new Proto(description);String path=apk.string(2);validPath(path);
                    if(!c.entries.containsKey(path)||!path.toLowerCase(Locale.ROOT).endsWith(".apk"))throw new IOException("TOC references a missing APK: "+path);
                    if(apk.has(3)){
                        Proto targeting=new Proto(apk.first(1));
                        if(targeting.has(5)||targeting.has(6)||targeting.has(8)||targeting.has(9)||targeting.has(10)||targeting.has(11)){unsupported="device-specific split targeting";break;}
                        if(splits.paths.contains(path))throw new IOException("TOC repeats an APK: "+path);splits.paths.add(path);
                    }else if(apk.has(4)){
                        if(!new Proto(apk.first(4)).string(3).isEmpty()){unsupported="standalone feature splits";break;}
                        Plan single=new Plan(id+"-apk-"+standalone.size(),label+" · "+new File(path).getName());single.paths.add(path);standalone.add(single);
                    }else{unsupported="instant, system, asset, archived or APEX APKs";break;}
                }
                if(unsupported!=null)break;
            }
            if(unsupported!=null){c.skipped.add(label+": unsupported "+unsupported);continue;}
            if(!splits.paths.isEmpty())c.plans.add(splits);c.plans.addAll(standalone);
        }
        if(c.plans.isEmpty())throw new IOException("No supported installable variant in this APKS. "+String.join("; ",c.skipped));
        return c;
    }

    private static void validateEntries(List<File> files)throws Exception {
        Map<String,String> hashes=new HashMap<>();Set<String> classes=new HashSet<>();long expanded=0;int count=0;
        for(File file:files)try(ZipFile zip=new ZipFile(file)){
            Set<String> names=new HashSet<>();boolean manifest=false;
            for(Enumeration<? extends ZipEntry> e=zip.entries();e.hasMoreElements();){
                ZipEntry entry=e.nextElement();String name=entry.getName();validPath(name);
                if(!names.add(name))throw new IOException("Duplicate APK entry: "+name);
                if(++count>MAX_ENTRIES)throw new IOException("Too many entries across the selected APKs");
                if(entry.isDirectory())continue;
                if(entry.getSize()<0||entry.getSize()>MAX_APK||(expanded+=entry.getSize())>MAX_TOTAL)throw new IOException("Expanded APK contents exceed the 1 GB conversion limit");
                if(name.equals("AndroidManifest.xml")){manifest=true;if(entry.getSize()>8*1024*1024)throw new IOException("Manifest is too large");}
                if(name.equals("resources.arsc")&&entry.getSize()>64*1024*1024)throw new IOException("Resource table exceeds the 64 MB conversion limit");
                boolean dex=name.matches("classes([2-9]|[1-9][0-9]+)?\\.dex");
                if(dex){
                    if(entry.getSize()>128*1024*1024)throw new IOException("DEX exceeds the 128 MB conversion limit");
                    try(InputStream in=zip.getInputStream(entry)){
                        byte[] data=FileOps.bytes(in,128*1024*1024);CRC32 crc=new CRC32();crc.update(data);
                        if(data.length!=entry.getSize()||crc.getValue()!=entry.getCrc())throw new IOException("Corrupt DEX entry: "+name);
                        DexBackedDexFile d=new DexBackedDexFile(Opcodes.getDefault(),data);
                        for(ClassDef cls:d.getClasses())if(!classes.add(cls.getType()))throw new IOException("Conflicting DEX class: "+cls.getType());
                    }
                }
                // ARSCLib merges resource tables and renumbers DEX. Other duplicate paths must be identical.
                if(dex)continue;
                MessageDigest digest=MessageDigest.getInstance("SHA-256");CRC32 crc=new CRC32();long size=0;
                try(InputStream in=zip.getInputStream(entry)){byte[] buffer=new byte[65536];int n;while((n=in.read(buffer))!=-1){if((size+=n)>MAX_APK)throw new IOException("APK entry is too large");digest.update(buffer,0,n);crc.update(buffer,0,n);}}
                if(size!=entry.getSize()||crc.getValue()!=entry.getCrc())throw new IOException("Corrupt APK entry: "+name);
                if(name.equals("AndroidManifest.xml")||name.equals("resources.arsc")||name.startsWith("META-INF/"))continue;
                String hash=Base64.getEncoder().encodeToString(digest.digest()),prior=hashes.putIfAbsent(name,hash);
                if(prior!=null&&!prior.equals(hash))throw new IOException("Conflicting split contents: "+name+". Select one compatible variant.");
            }
            if(!manifest)throw new IOException("An embedded APK has no AndroidManifest.xml");
        }
    }
    private static long copyChecked(InputStream in,OutputStream out,long limit,ZipEntry entry)throws IOException {
        CRC32 crc=new CRC32();byte[] buffer=new byte[65536];long total=0;int n;
        while((n=in.read(buffer))!=-1){if((total+=n)>limit)throw new IOException("Selected APKs exceed conversion size limits");crc.update(buffer,0,n);out.write(buffer,0,n);}
        if(total!=entry.getSize()||crc.getValue()!=entry.getCrc())throw new IOException("Corrupt APKS entry: "+entry.getName());return total;
    }
    private static void validPath(String path)throws IOException {
        if(path.isEmpty()||path.startsWith("/")||path.indexOf('\\')>=0||path.indexOf('\0')>=0||path.indexOf(':')>=0)throw new IOException("Unsafe archive path");
        for(String part:path.split("/"))if(part.equals("..")||part.equals("."))throw new IOException("Unsafe archive path: "+path);
    }
    private static String attribute(ResXmlElement element,String name){
        if(element==null)return "";for(Iterator<ResXmlAttribute> it=element.getAttributes();it.hasNext();){ResXmlAttribute a=it.next();if(name.equals(a.getName())){String value=a.getValueAsString();return value!=null?value:a.getValueType().toString().contains("BOOLEAN")?String.valueOf(a.getValueAsBoolean()):String.valueOf(a.getData());}}return "";
    }
    private static void addTypes(Set<String> result,String value){for(String s:value.split(","))if(!s.trim().isEmpty())result.add(s.trim());}
    private static void sanitize(ResXmlElement element){
        if(element==null)return;
        Set<String> names=new HashSet<>(Arrays.asList("split","splitName","configForSplit","isFeatureSplit","isSplitRequired","isolatedSplits","splitTypes","requiredSplitTypes"));
        element.removeAttributeIf(a->names.contains(a.getName()));
        List<ResXmlElement> children=new ArrayList<>();element.getElements().forEachRemaining(children::add);
        for(ResXmlElement child:children){String name=attribute(child,"name");if("uses-split".equals(child.getName())||("meta-data".equals(child.getName())&&Arrays.asList("com.android.vending.splits","com.android.vending.splits.required","com.android.vending.derived.apk.id","com.android.stamp.source","com.android.stamp.type").contains(name)))child.removeSelf();else sanitize(child);}
    }

    // Small bounded reader for bundletool's public commands.proto; unknown fields are skipped.
    // Variants are deliberately separate plans: mutually exclusive base APKs are never combined.
    private static final class Proto {
        final Map<Integer,List<byte[]>> bytes=new HashMap<>();final Map<Integer,Long> numbers=new HashMap<>();
        Proto(byte[] data)throws IOException{
            CodedInputStream in=CodedInputStream.newInstance(data);int count=0,tag;
            while((tag=in.readTag())!=0){if(++count>20000)throw new IOException("Oversized bundle TOC");int field=tag>>>3,wire=tag&7;
                if(wire==2)bytes.computeIfAbsent(field,k->new ArrayList<>()).add(in.readByteArray());
                else if(wire==0)numbers.put(field,in.readInt64());
                else if(wire==1||wire==5)in.skipField(tag);else throw new IOException("Invalid bundle TOC");
            }
        }
        boolean has(int field){return bytes.containsKey(field)||numbers.containsKey(field);}boolean empty(){return bytes.isEmpty()&&numbers.isEmpty();}
        List<byte[]> values(int field){return bytes.getOrDefault(field,Collections.emptyList());}
        byte[] first(int field){List<byte[]> list=values(field);return list.isEmpty()?new byte[0]:list.get(0);}
        String string(int field){return new String(first(field),java.nio.charset.StandardCharsets.UTF_8);}
        long number(int field){return numbers.getOrDefault(field,0L);}
    }
    private static String targetLabel(byte[] bytes)throws IOException {
        Proto target=new Proto(bytes);StringBuilder label=new StringBuilder();
        Proto sdk=new Proto(target.first(1));List<String> levels=new ArrayList<>();
        for(byte[] value:sdk.values(1)){Proto version=new Proto(value);levels.add(String.valueOf(new Proto(version.first(1)).number(1)));}
        if(!levels.isEmpty())label.append(" · API ").append(String.join(",",levels)).append("+");
        List<String> abis=new ArrayList<>();String[] names={"unspecified","armeabi","armeabi-v7a","arm64-v8a","x86","x86_64","mips","mips64","riscv64"};
        for(byte[] value:new Proto(target.first(2)).values(1)){int n=(int)new Proto(value).number(1);abis.add(n>=0&&n<names.length?names[n]:"ABI "+n);}
        if(!abis.isEmpty())label.append(" · ").append(String.join(",",abis));return label.toString();
    }
}
