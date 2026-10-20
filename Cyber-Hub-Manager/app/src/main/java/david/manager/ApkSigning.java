package david.manager;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import com.android.apksig.*;

/** Publishes an APK only after all requested signature schemes verify. */
public final class ApkSigning {
 private ApkSigning() {}
 /** Optional user signing key (PKCS12). When set it is used instead of the bundled development key. */
 static volatile byte[] customP12;static volatile char[] customPass,customKeyPass;static volatile String customAlias;
 static void useCustom(byte[] p12,char[] pass,char[] keyPass,String alias){customP12=p12;customPass=pass;customKeyPass=keyPass;customAlias=alias;}
 static void clearCustom(){customP12=null;customPass=null;customKeyPass=null;customAlias=null;}
 static String firstKey(KeyStore store)throws Exception{for(Enumeration<String> e=store.aliases();e.hasMoreElements();){String a=e.nextElement();if(store.isKeyEntry(a))return a;}throw new IOException("Keystore has no private key");}
 public static void sign(File source, File destination, InputStream keyStream) throws Exception {
  if(destination.exists())throw new IOException("Signed output already exists");
  File parent=destination.getAbsoluteFile().getParentFile();
  File temporary=File.createTempFile(".verified-sign-",".apk",parent);
  try {
   KeyStore store=KeyStore.getInstance("PKCS12");char[] password="cyberhub-development".toCharArray();String alias;
   byte[] custom=customP12;
   if(custom!=null){password=customKeyPass!=null?customKeyPass:customPass;store.load(new ByteArrayInputStream(custom),customPass);alias=customAlias!=null&&store.isKeyEntry(customAlias)?customAlias:firstKey(store);}
   else{store.load(keyStream,password);alias=store.aliases().nextElement();}
   ApkSigner.SignerConfig signer=new ApkSigner.SignerConfig.Builder("CyberHubDevelopment",(PrivateKey)store.getKey(alias,password),Collections.singletonList((X509Certificate)store.getCertificate(alias))).build();
   new ApkSigner.Builder(Collections.singletonList(signer)).setInputApk(source).setOutputApk(temporary).setV1SigningEnabled(true).setV2SigningEnabled(true).setV3SigningEnabled(true).setMinSdkVersion(21).build().sign();
   ApkVerifier.Result result=new ApkVerifier.Builder(temporary).setMinCheckedPlatformVersion(21).build().verify();
   if(!result.isVerified()||!result.isVerifiedUsingV1Scheme()||!result.isVerifiedUsingV2Scheme()||!result.isVerifiedUsingV3Scheme())throw new IOException("APK signature verification failed: "+result.getErrors());
   if(destination.exists())throw new IOException("Output was created by another operation");
   FileOps.replace(temporary,destination);
  }finally{temporary.delete();}
 }
}
