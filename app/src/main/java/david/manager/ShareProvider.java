package david.manager;
import android.content.*;import android.database.*;import android.net.Uri;import android.os.*;import android.provider.OpenableColumns;import java.io.*;
public class ShareProvider extends ContentProvider {
 public boolean onCreate(){return true;}
 private File file(Uri uri)throws FileNotFoundException{try{String name=uri.getLastPathSegment();File root=new File(getContext().getCacheDir(),"shared");File f=FileOps.child(root,name);if(!f.isFile())throw new IOException("File not found");return f;}catch(Exception e){throw new FileNotFoundException("File unavailable");}}
 public ParcelFileDescriptor openFile(Uri uri,String mode)throws FileNotFoundException{if(!"r".equals(mode))throw new FileNotFoundException("Read only");return ParcelFileDescriptor.open(file(uri),ParcelFileDescriptor.MODE_READ_ONLY);}
 public String getType(Uri uri){return uri.toString().endsWith(".apk")?"application/vnd.android.package-archive":"application/octet-stream";}
 public Cursor query(Uri uri,String[] projection,String selection,String[] args,String order){try{File f=file(uri);String[] cols=projection==null?new String[]{OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE}:projection;MatrixCursor c=new MatrixCursor(cols);Object[] row=new Object[cols.length];for(int i=0;i<cols.length;i++)row[i]=cols[i].equals(OpenableColumns.DISPLAY_NAME)?f.getName():cols[i].equals(OpenableColumns.SIZE)?f.length():null;c.addRow(row);return c;}catch(Exception e){return null;}}
 public Uri insert(Uri u,ContentValues v){throw new UnsupportedOperationException();}public int update(Uri u,ContentValues v,String s,String[] a){throw new UnsupportedOperationException();}public int delete(Uri u,String s,String[] a){throw new UnsupportedOperationException();}
}
