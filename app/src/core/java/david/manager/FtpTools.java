package david.manager;
import org.apache.commons.net.ftp.*;import org.json.*;import java.io.*;
public final class FtpTools {
 public static Object call(JSONObject a)throws Exception{FTPClient client=a.optBoolean("tls",true)?new FTPSClient(false):new FTPClient();client.setConnectTimeout(15000);client.setDefaultTimeout(15000);client.setDataTimeout(java.time.Duration.ofSeconds(30));try{
  if(client instanceof FTPSClient)((FTPSClient)client).setEndpointCheckingEnabled(true);
  client.connect(a.getString("host"),a.optInt("port",21));if(!client.login(a.getString("user"),a.optString("password")))throw new IOException("FTP login failed");if(client instanceof FTPSClient){((FTPSClient)client).execPBSZ(0);((FTPSClient)client).execPROT("P");}client.enterLocalPassiveMode();client.setFileType(FTP.BINARY_FILE_TYPE);String op=a.optString("op","list"),path=a.optString("remote","/");
  if(op.equals("list")){JSONArray arr=new JSONArray();for(FTPFile f:client.listFiles(path))if(!f.getName().equals(".")&&!f.getName().equals(".."))arr.put(new JSONObject().put("name",f.getName()).put("dir",f.isDirectory()).put("size",f.getSize()));return arr;}
  if(op.equals("download")){File dst=new File(a.getString("local"));if(dst.exists())throw new IOException("Local file already exists");try(OutputStream out=new FileOutputStream(dst)){if(!client.retrieveFile(path,out))throw new IOException(client.getReplyString());}catch(Exception e){dst.delete();throw e;}return dst.getPath();}
  if(op.equals("upload")){try(InputStream in=new FileInputStream(a.getString("local"))){if(!client.storeFile(path,in))throw new IOException(client.getReplyString());}return true;}
  throw new IOException("Unknown FTP operation");
 }finally{try{client.logout();client.disconnect();}catch(Exception ignored){}}}
}
