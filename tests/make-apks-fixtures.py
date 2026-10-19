"""Generate real aapt2 binary resource splits; no third-party APK is used."""
from pathlib import Path
import os, subprocess
P=Path(__file__).resolve().parents[1];T=P.parent/'toolchain'
sdk=Path(os.environ.get('ANDROID_HOME',os.environ.get('ANDROID_SDK_ROOT',str(T))))
android=sdk/'platforms/android-34/android.jar'
if not android.exists():android=T/'android-34/android.jar'
aapt=sdk/'build-tools/34.0.0/aapt2'
if not aapt.exists():aapt=T/'android-14/aapt2'
root=P/'tests/fixtures/apks';root.mkdir(parents=True,exist_ok=True)
for config,text in [('values','Base message'),('values-fr','Bonjour split')]:
 d=root/'res'/config;d.mkdir(parents=True,exist_ok=True)
 (d/'strings.xml').write_text('<resources><string name="message">'+text+'</string></resources>')
(root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="demo.bundle" android:versionCode="7" android:versionName="1.0"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="28"/><application android:label="@string/message"/></manifest>')
prefix=['/lib64/ld-linux-x86-64.so.2',str(aapt)] if Path('/lib64/ld-linux-x86-64.so.2').exists() else [str(aapt)]
subprocess.run(prefix+['compile','--dir',str(root/'res'),'-o',str(root/'compiled.zip')],check=True)
subprocess.run(prefix+['link','-I',str(android),'--manifest',str(root/'AndroidManifest.xml'),'-o',str(root/'base.apk'),'--split',str(root/'config-fr.apk')+':fr',str(root/'compiled.zip')],check=True)
