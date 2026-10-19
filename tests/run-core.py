"""Run after tools/build.py; optional first argument is a reference resource ZIP."""
import subprocess,os,sys,uuid,urllib.request,shutil
from pathlib import Path
P=Path(__file__).resolve().parents[1];T=P.parent/'toolchain';B=P/'.build';env=dict(os.environ)
if Path('/usr/lib/jvm/java-17-openjdk-amd64/lib').exists():env['LD_LIBRARY_PATH']='/usr/lib/jvm/java-17-openjdk-amd64/lib:/usr/lib/jvm/java-17-openjdk-amd64/lib/server'
sdk=Path(os.environ.get('ANDROID_HOME',os.environ.get('ANDROID_SDK_ROOT',str(T))))
android=sdk/'platforms/android-34/android.jar'
if not android.exists():android=T/'android-34/android.jar'
ecj=T/'ecj.jar'
if not ecj.exists():ecj=B/'ecj.jar'
jsonjar=B/'json-test.jar'
if not jsonjar.exists():urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/org/json/json/20240303/json-20240303.jar',jsonjar)
api=B/'android-api.jar'
desktop=B/'new-libs/zstd-jni-desktop.jar'
if not desktop.exists():
 desktop.parent.mkdir(parents=True,exist_ok=True);urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/com/github/luben/zstd-jni/1.5.7-6/zstd-jni-1.5.7-6.jar',desktop)
cp=os.pathsep.join(map(str,[B/'new-libs/zstd-jni-desktop.jar',jsonjar,B/'classes',android,*sorted((P/'app/libs').glob('*.jar'))]))
compilecp=os.pathsep.join(map(str,[jsonjar,B/'classes',api,*sorted((P/'app/libs').glob('*.jar'))]))
shutil.rmtree(B/'testclasses',ignore_errors=True)
(B/'testclasses').mkdir()
subprocess.run(['java','-jar',str(ecj),'-11','-proc:none','-nowarn','-cp',compilecp,'-d',str(B/'testclasses'),*map(str,(P/'tests').glob('*SmokeTest.java'))],env=env,check=True)
target=B/('core-test-'+uuid.uuid4().hex[:8]);reference=sys.argv[1] if len(sys.argv)>1 else str(P/'tests/fixtures/resources.zip')
run=['java','-Djava.io.tmpdir='+str(B/'tmp'),'-cp',str(B/'testclasses')+os.pathsep+cp]
subprocess.run(run+['david.manager.CoreSmokeTest',str(target),reference],env=env,check=True)
subprocess.run(run+['david.manager.ApkSmokeTest',str(P/'dist/DB-Manager-0.1.9.apk'),str(target/'roundtrip.apk'),str(P/'app/src/main/assets/development-signing.p12')],env=env,check=True)

subprocess.run(run+['david.manager.DexTreeSmokeTest',str(target)],env=env,check=True)

subprocess.run(run+['david.manager.VideoFeaturesSmokeTest',str(target)],env=env,check=True)

subprocess.run(run+['david.manager.JavaFlowSmokeTest',str(target),str(P/'app/src/main/assets/compiler/android-api.jar'),str(P/'app/src/main/assets/development-signing.p12')],env=env,check=True)

subprocess.run([sys.executable,str(P/"tests/make-apks-fixtures.py")],env=env,check=True)
subprocess.run(run+["david.manager.ApksSmokeTest",str(target),str(P/"tests/fixtures/apks"),str(P/"app/src/main/assets/development-signing.p12")],env=env,check=True)
subprocess.run(run+['david.manager.ApkToolsSmokeTest',str(target),str(P/'tests/fixtures/apks')],env=env,check=True)
subprocess.run(run+['david.manager.ApkProtectSmokeTest',str(target),str(P/'tests/fixtures/apks'),str(api)],env=env,check=True)
