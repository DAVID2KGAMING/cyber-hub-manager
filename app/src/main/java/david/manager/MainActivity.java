package david.manager;

import android.app.*;
import android.os.*;
import android.Manifest;
import android.content.*;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.provider.Settings;
import android.webkit.*;
import android.view.*;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class MainActivity extends Activity {
    private WebView web;
    private DataEngine engine;
    private static final String APP_URL="https://appassets.androidplatform.net/assets/app.html";
    private final ExecutorService worker=Executors.newFixedThreadPool(2);
    private final ExecutorService thumbnails=Executors.newSingleThreadExecutor();
    @Override public void onCreate(Bundle state){super.onCreate(state);
        System.setProperty("java.io.tmpdir",getCacheDir().getPath());
        try{engine=new DataEngine(this);web=new WebView(this);web.setBackgroundColor(0xff303030);
        WebSettings s=web.getSettings();s.setJavaScriptEnabled(true);s.setDomStorageEnabled(true);s.setAllowFileAccess(false);s.setAllowContentAccess(false);s.setAllowFileAccessFromFileURLs(false);s.setAllowUniversalAccessFromFileURLs(false);s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);s.setTextZoom(100);s.setSupportZoom(false);s.setBuiltInZoomControls(false);s.setDisplayZoomControls(false);
        web.setWebChromeClient(new WebChromeClient(){@Override public boolean onConsoleMessage(ConsoleMessage m){
            if(m.messageLevel()==ConsoleMessage.MessageLevel.ERROR)android.util.Log.e("CyberHubUI",m.message()+" @ "+m.sourceId()+":"+m.lineNumber());return true;
        }});
        web.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest r){return !APP_URL.equals(r.getUrl().toString());}
            @Override public WebResourceResponse shouldInterceptRequest(WebView v,WebResourceRequest r){return localAsset(r.getUrl(),r.getMethod());}
            @Override public void onReceivedError(WebView v,WebResourceRequest r,WebResourceError e){if(r.isForMainFrame())showStartupError("Unable to load the interface: "+e.getDescription());}
            @Override public void onPageFinished(WebView v,String url){
                if(APP_URL.equals(url))v.evaluateJavascript("typeof window.CyberBoot === 'object'",result->{if(!"true".equals(result))showStartupError("The interface startup script did not load.");});
            }
            @Override public boolean onRenderProcessGone(WebView v,RenderProcessGoneDetail detail){
                if(web==v){web=null;v.destroy();}showStartupError("Android WebView stopped. Tap Retry to reopen the app.");return true;
            }
        });
        web.addJavascriptInterface(new Bridge(),"CyberNative");setContentView(web);web.loadUrl(APP_URL);
        }catch(Throwable error){showStartupError(error.getClass().getSimpleName()+": "+error.getMessage());}
    }
    private WebResourceResponse localAsset(Uri uri,String method){
        String path=uri.getPath();
        if("GET".equals(method)&&"https".equals(uri.getScheme())&&"appassets.androidplatform.net".equals(uri.getHost())&&(uri.getPort()==-1||uri.getPort()==443)&&path!=null&&path.startsWith("/assets/")){
            String name=path.substring(8);
            if(Arrays.asList("app.html","app.js","boot.js","style.css","vendor/codemirror.js","vendor/codemirror.css","vendor/clike.js","vendor/xml.js","vendor/searchcursor.js").contains(name)){
                try{
                    String mime=name.endsWith(".html")?"text/html":name.endsWith(".css")?"text/css":"application/javascript";
                    return new WebResourceResponse(mime,"UTF-8",200,"OK",Collections.singletonMap("Cache-Control","no-store"),getAssets().open(name));
                }catch(IOException ignored){}
            }
        }
        // No network fallback, arbitrary local files, or signing-key exposure through WebView.
        return new WebResourceResponse("text/plain","UTF-8",404,"Not Found",Collections.emptyMap(),new ByteArrayInputStream("Not found".getBytes(StandardCharsets.UTF_8)));
    }
    private void showStartupError(String message){
        android.widget.LinearLayout box=new android.widget.LinearLayout(this);box.setOrientation(android.widget.LinearLayout.VERTICAL);box.setPadding(32,40,32,24);box.setBackgroundColor(0xff303030);
        android.content.pm.PackageInfo provider=WebView.getCurrentWebViewPackage();
        String details="DB Manager 0.2.3\n\n"+message+"\n\nAndroid "+Build.VERSION.RELEASE+"\nWebView: "+(provider==null?"unavailable":provider.packageName+" "+provider.versionName);
        android.widget.TextView text=new android.widget.TextView(this);text.setText(details);text.setTextColor(0xffdddddd);text.setTextSize(16);text.setTextIsSelectable(true);box.addView(text);
        android.widget.Button retry=new android.widget.Button(this);retry.setText("Retry");retry.setOnClickListener(v->recreate());box.addView(retry);
        android.widget.Button copy=new android.widget.Button(this);copy.setText("Copy error details");copy.setOnClickListener(v->{((android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("Startup error",details));toast("Error details copied");});box.addView(copy);
        android.widget.ScrollView scroll=new android.widget.ScrollView(this);scroll.addView(box);setContentView(scroll);
    }
    void bundleProgress(String job,String message){
        runOnUiThread(()->{if(web!=null)web.evaluateJavascript("window.bundleProgress&&window.bundleProgress("+JSONObject.quote(job)+","+JSONObject.quote(message)+")",null);});
    }
    public final class Bridge {
        @JavascriptInterface public void request(String id,String action,String args){
            (action.equals("apkIcon")?thumbnails:worker).execute(()->{JSONObject response=new JSONObject();try{
                JSONObject a=new JSONObject(args);Object result;
                switch(action){
                    case "apkIcon":result=engine.iconForPath(a.getString("path"));break;
                    case "exit":runOnUiThread(()->finish());result=true;break;
                    case "permission":runOnUiThread(()->storagePermission());result=true;break;
                    case "install":{File f=new File(a.getString("path"));if(!f.isFile())throw new IOException("APK not found");File shared=shareCopy(f);runOnUiThread(()->install(shared));result=true;break;}
                    case "shareMultiple":{ArrayList<Uri>uris=new ArrayList<>();JSONArray paths=a.getJSONArray("paths");for(int i=0;i<paths.length();i++)uris.add(shareUri(shareCopy(new File(paths.getString(i)))));if(uris.isEmpty())throw new IOException("No files selected");runOnUiThread(()->{try{Intent intent=new Intent(Intent.ACTION_SEND_MULTIPLE).setType("application/octet-stream").putParcelableArrayListExtra(Intent.EXTRA_STREAM,uris).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);ClipData clip=ClipData.newRawUri("Files",uris.get(0));for(int i=1;i<uris.size();i++)clip.addItem(new ClipData.Item(uris.get(i)));intent.setClipData(clip);startActivity(Intent.createChooser(intent,"Share files"));}catch(Exception error){toast(error.getMessage());}});result=true;break;}
                    case "share":{File shared=shareCopy(new File(a.getString("path")));runOnUiThread(()->share(shared));result=true;break;}
                    case "clipboard":runOnUiThread(()->((android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("Cyber Hub Manager",a.optString("text"))));result=true;break;
                    default:result=engine.call(action,a);
                }
                response.put("id",id);response.put("ok",true);response.put("data",result==null?JSONObject.NULL:result);
            }catch(Throwable e){try{response.put("id",id);response.put("ok",false);response.put("error",e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());}catch(JSONException ignored){}}
            final String json=response.toString();runOnUiThread(()->{if(web!=null)web.evaluateJavascript("window.receive&&window.receive("+json+")",null);});
            });
        }
    }
    private File shareCopy(File src)throws IOException{File root=new File(getCacheDir(),"shared");root.mkdirs();File dst=FileOps.child(root,src.getName());java.nio.file.Files.copy(src.toPath(),dst.toPath(),java.nio.file.StandardCopyOption.REPLACE_EXISTING);return dst;}
    private Uri shareUri(File f){return new Uri.Builder().scheme("content").authority(getPackageName()+".files").appendPath(f.getName()).build();}
    private void install(File f){try{
        if(Build.VERSION.SDK_INT>=26&&!getPackageManager().canRequestPackageInstalls()){startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:"+getPackageName())));toast("Allow installs, then tap Install again");return;}
        Intent i=new Intent(Intent.ACTION_VIEW).setDataAndType(shareUri(f),"application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);startActivity(i);
    }catch(Exception e){toast(e.getMessage());}}
    private void share(File f){try{Intent i=new Intent(Intent.ACTION_SEND).setType("application/octet-stream").putExtra(Intent.EXTRA_STREAM,shareUri(f)).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);startActivity(Intent.createChooser(i,"Share file"));}catch(Exception e){toast(e.getMessage());}}
    private void storagePermission(){try{if(Build.VERSION.SDK_INT>=30)startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,Uri.parse("package:"+getPackageName())));else requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE,Manifest.permission.WRITE_EXTERNAL_STORAGE},10);}catch(Exception e){startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));}}
    private void toast(String s){android.widget.Toast.makeText(this,s,android.widget.Toast.LENGTH_LONG).show();}
    @Override protected void onResume(){super.onResume();if(web!=null)web.evaluateJavascript("window.onNativeResume&&window.onNativeResume()",null);}
    @Override public void onBackPressed(){if(web!=null)web.evaluateJavascript("window.goBack&&window.goBack()",null);}
    @Override protected void onDestroy(){if(engine!=null)engine.close();worker.shutdownNow();thumbnails.shutdownNow();if(web!=null){web.removeJavascriptInterface("CyberNative");web.destroy();web=null;}super.onDestroy();}
}
