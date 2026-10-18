#!/usr/bin/env python3
"""Fetch pinned Maven runtime dependencies without requiring Gradle/Maven."""
import urllib.request, xml.etree.ElementTree as ET, re, concurrent.futures, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; CACHE=ROOT/'.build/poms'; LIB=ROOT/'app/libs'
CACHE.mkdir(parents=True,exist_ok=True);LIB.mkdir(parents=True,exist_ok=True)
NS={'m':'http://maven.apache.org/POM/4.0.0'}
models={}
def download(g,a,v,ext):
 path=f"{g.replace('.','/')}/{a}/{v}/{a}-{v}.{ext}"
 bases=['https://dl.google.com/dl/android/maven2/'] if g.startswith('com.android') else ['https://repo.maven.apache.org/maven2/']
 for base in bases:
  try:return urllib.request.urlopen(base+path,timeout=90).read()
  except Exception as e:last=e
 raise last
def model(g,a,v):
 key=(g,a,v)
 if key in models:return models[key]
 path=CACHE/f'{g}.{a}-{v}.pom'
 if not path.exists():path.write_bytes(download(g,a,v,'pom'))
 root=ET.fromstring(path.read_bytes());props={};mgmt={}
 par=root.find('m:parent',NS)
 if par is not None:
  def pt(n):return par.findtext('m:'+n,namespaces=NS)
  pp,pm,_=model(pt('groupId'),pt('artifactId'),pt('version'));props.update(pp);mgmt.update(pm)
 props.update({'project.groupId':g,'project.artifactId':a,'project.version':v,'pom.version':v})
 pe=root.find('m:properties',NS)
 if pe is not None:
  for ch in pe:props[ch.tag.split('}')[-1]]=ch.text or ''
 def sub(s):
  for _ in range(12):
   newer=re.sub(r'\$\{([^}]+)\}',lambda m:props.get(m[1],m[0]),s or '')
   if newer==s:return newer
   s=newer
  return s
 def parse(dep):
  def t(n):return sub(dep.findtext('m:'+n,'',NS))
  dg,da=t('groupId'),t('artifactId');dv=t('version') or mgmt.get((dg,da),'')
  return dg,da,dv,t('scope'),t('optional'),t('type') or 'jar'
 for d in root.findall('m:dependencyManagement/m:dependencies/m:dependency',NS):
  dg,da,dv,scope,opt,typ=parse(d)
  if typ=='pom' and scope=='import':mgmt.update(model(dg,da,dv)[1])
  else:mgmt[dg,da]=dv
 deps=[]
 for d in root.findall('m:dependencies/m:dependency',NS):
  dg,da,dv,scope,opt,typ=parse(d)
  if scope not in ['test','provided','system'] and opt!='true' and typ=='jar':deps.append((dg,da,dv))
 result=(props,mgmt,deps);models[key]=result;return result
roots=[('io.github.reandroid','ARSCLib','1.4.0'),('org.eclipse.jdt.core.compiler','ecj','4.6.1'),('com.jakewharton.android.repackaged','dalvik-dx','14.0.0_r21'),('org.ow2.asm','asm','9.7.1'),('io.github.skylot','jadx-core','1.4.7'),('io.github.skylot','jadx-dex-input','1.4.7'),('org.smali','baksmali','2.5.2'),('org.smali','smali','2.5.2'),('commons-net','commons-net','3.10.0'),('org.slf4j','slf4j-nop','2.0.6'),('com.google.guava','guava','31.1-android'),('com.android.tools.build','apksig','8.2.2'),('org.apache.commons','commons-compress','1.28.0'),('org.tukaani','xz','1.10'),('commons-io','commons-io','2.20.0'),('org.apache.commons','commons-lang3','3.18.0'),('commons-codec','commons-codec','1.19.0'),('net.lingala.zip4j','zip4j','2.11.5')]
pins={(g,a):v for g,a,v in roots};pins['org.slf4j','slf4j-api']='2.0.6'
queue=list(roots);seen={}
while queue:
 g,a,v=queue.pop(0);v=pins.get((g,a),v)
 if (g,a) in seen or g in ('junit','org.hamcrest'):continue
 if not v or '${' in v:raise RuntimeError(f'Unresolved version: {g}:{a}:{v}')
 seen[g,a]=v;print('Resolve',g,a,v,flush=True);queue.extend(model(g,a,v)[2])
def jar(item):
 (g,a),v=item;p=LIB/f'{a}-{v}.jar'
 if not p.exists():p.write_bytes(download(g,a,v,'jar'))
 print('Fetched',p.name,flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(jar,seen.items()))
(ROOT/'DEPENDENCIES.json').write_text(json.dumps([{'group':g,'artifact':a,'version':v} for (g,a),v in seen.items()],indent=2)+'\n')

# Android Zstandard JNI AAR; package its Java API and four Android ABIs.
import zipfile, io
g,a,v='com.github.luben','zstd-jni','1.5.7-6'
with zipfile.ZipFile(io.BytesIO(download(g,a,v,'aar'))) as z:
 for n in z.namelist():
  if n=='classes.jar':(LIB/f'{a}-{v}.jar').write_bytes(z.read(n))
  elif n.startswith('jni/') and n.endswith('.so'):
   p=ROOT/'app/src/main/jniLibs'/n[4:];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(n))
p=ROOT/'DEPENDENCIES.json';deps=json.loads(p.read_text());deps.append({'group':g,'artifact':a,'version':v});p.write_text(json.dumps(deps,indent=2)+'\n')
