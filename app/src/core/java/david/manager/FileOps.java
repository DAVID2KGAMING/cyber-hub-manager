package david.manager;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

/** File operations used by both the device bridge and the desktop smoke tests. */
public final class FileOps {
    public static final long MAX_TEXT = 8L * 1024 * 1024;
    public static final long MAX_EXTRACT = 1024L * 1024 * 1024;
    private FileOps() {}
    public static byte[] read(File f, long limit) throws IOException {
        if (f.length() > limit) throw new IOException("File is too large for this operation (limit " + limit / 1048576 + " MB)");
        try (InputStream in = new FileInputStream(f)) { return bytes(in, limit); }
    }
    public static byte[] bytes(InputStream in, long limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); copy(in, out, limit); return out.toByteArray();
    }
    public static long copy(InputStream in, OutputStream out, long limit) throws IOException {
        byte[] b = new byte[32768]; int n; long count = 0;
        while ((n = in.read(b)) != -1) { count += n; if (count > limit) throw new IOException("Operation exceeds size limit"); out.write(b, 0, n); }
        return count;
    }
    public static File child(File parent, String name) throws IOException {
        if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf('\0') >= 0)
            throw new IOException("Enter a single file or folder name");
        File f = new File(parent, name);
        if (!f.getCanonicalFile().getParentFile().equals(parent.getCanonicalFile())) throw new IOException("Invalid path");
        return f;
    }
    public static File contained(File root, String name) throws IOException {
        File f = new File(root, name).getCanonicalFile();
        if (!f.toPath().startsWith(root.getCanonicalFile().toPath()) || f.equals(root.getCanonicalFile())) throw new IOException("Unsafe archive path: " + name);
        return f;
    }
    public static void writeAtomic(File file, byte[] data, boolean backup) throws IOException {
        File parent = file.getAbsoluteFile().getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs()) throw new IOException("Cannot create destination directory");
        File temp = File.createTempFile(".cyber-", ".tmp", parent);
        try {
            try (FileOutputStream out = new FileOutputStream(temp)) { out.write(data); out.getFD().sync(); }
            if (backup && file.exists()) Files.copy(file.toPath(), new File(file + ".bak").toPath(), StandardCopyOption.REPLACE_EXISTING);
            replace(temp, file);
        } finally { temp.delete(); }
    }
    public static void replace(File temp, File dest) throws IOException {
        try { Files.move(temp.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
        catch (AtomicMoveNotSupportedException e) { Files.move(temp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING); }
    }
    public static void copyTree(File src, File dst) throws IOException {
        if (Files.isSymbolicLink(src.toPath())) throw new IOException("Symbolic links are not copied");
        if (dst.getCanonicalFile().toPath().startsWith(src.getCanonicalFile().toPath())) throw new IOException("Destination is inside the source");
        if (dst.exists()) throw new IOException("Destination already exists: " + dst.getName());
        copyTreeInner(src, dst);
    }
    private static void copyTreeInner(File src, File dst) throws IOException {
        if (Files.isSymbolicLink(src.toPath())) throw new IOException("Symbolic link encountered: " + src.getName());
        if (src.isDirectory()) {
            if (!dst.mkdir()) throw new IOException("Cannot create " + dst);
            File[] files = src.listFiles(); if (files == null) throw new IOException("Cannot read " + src);
            for (File f : files) copyTreeInner(f, new File(dst, f.getName()));
        } else Files.copy(src.toPath(), dst.toPath());
    }
    public static void deleteTree(File f) throws IOException {
        if (!Files.isSymbolicLink(f.toPath()) && f.isDirectory()) {
            File[] fs = f.listFiles(); if (fs == null) throw new IOException("Cannot list " + f);
            for (File c : fs) deleteTree(c);
        }
        if (!f.delete() && f.exists()) throw new IOException("Cannot delete " + f);
    }
    public static void extract(File archive, File dest) throws IOException {
        if (dest.exists()) throw new IOException("Extraction folder already exists");
        if (!dest.mkdirs()) throw new IOException("Cannot create extraction folder");
        long total = 0; int count = 0;
        try (ZipFile z = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement(); if (++count > 100000) throw new IOException("Too many archive entries");
                File out = contained(dest, e.getName());
                if (e.isDirectory()) { if (!out.isDirectory() && !out.mkdirs()) throw new IOException("Cannot create folder"); continue; }
                if (!out.getParentFile().isDirectory() && !out.getParentFile().mkdirs()) throw new IOException("Cannot create folder");
                try (InputStream in = z.getInputStream(e); OutputStream os = new FileOutputStream(out)) { total += copy(in, os, MAX_EXTRACT - total); }
            }
        } catch (IOException e) { try { deleteTree(dest); } catch (IOException ignored) {} throw e; }
    }
    public static byte[] zipEntry(File archive, String entry, long max) throws IOException {
        try (ZipFile z = new ZipFile(archive)) {
            ZipEntry e = z.getEntry(entry); if (e == null || e.isDirectory()) throw new IOException("Archive file not found");
            if (e.getSize() > max) throw new IOException("Archive entry exceeds size limit");
            try (InputStream in = z.getInputStream(e)) { return bytes(in, max); }
        }
    }
    /** Writes a new archive and removes obsolete JAR signatures after an edit. Original is kept. */
    public static void rewriteZip(File src, File dst, Map<String, byte[]> replacements) throws IOException { rewriteZip(src, dst, replacements, Collections.<String>emptySet()); }
    public static void rewriteZip(File src, File dst, Map<String, byte[]> replacements, Set<String> removals) throws IOException {
        if (src.getCanonicalFile().equals(dst.getCanonicalFile())) throw new IOException("Use a separate output archive");
        File temp = File.createTempFile(".archive-", ".zip", dst.getAbsoluteFile().getParentFile());
        Set<String> seen = new HashSet<>();
        try {
            try (ZipFile input = new ZipFile(src); CountedOutput counter = new CountedOutput(new FileOutputStream(temp)); ZipOutputStream out = new ZipOutputStream(counter)) {
                Enumeration<? extends ZipEntry> en = input.entries();
                while (en.hasMoreElements()) {
                    ZipEntry old = en.nextElement(); String name = old.getName();
                    if (!seen.add(name)) throw new IOException("Duplicate archive entry: " + name);
                    if (removals.contains(name)) continue;
                    if (name.matches("(?i)META-INF/[^/]+\\.(SF|RSA|DSA|EC)") || name.equalsIgnoreCase("META-INF/MANIFEST.MF")) continue;
                    ZipEntry next = new ZipEntry(name); next.setTime(Math.max(old.getTime(),315619200000L));
                    if (old.getMethod() == ZipEntry.STORED) {
                        next.setMethod(ZipEntry.STORED);
                        byte[] replacement = replacements.get(name);
                        if (replacement != null) { CRC32 crc = new CRC32(); crc.update(replacement); next.setSize(replacement.length); next.setCompressedSize(replacement.length); next.setCrc(crc.getValue()); }
                        else { next.setSize(old.getSize()); next.setCompressedSize(old.getSize()); next.setCrc(old.getCrc()); }
                        int alignment = name.startsWith("lib/") && name.endsWith(".so") ? 16384 : 4;
                        long dataStart = counter.count + 30 + name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                        int padding = (int)((alignment - (dataStart % alignment)) % alignment);
                        if (padding > 0) { if (padding < 4) padding += alignment; byte[] extra = new byte[padding]; extra[0] = 0x35; extra[1] = (byte)0xd9; extra[2] = (byte)(padding - 4); extra[3] = (byte)((padding - 4) >>> 8); next.setExtra(extra); }
                    }
                    out.putNextEntry(next);
                    if (replacements.containsKey(name)) out.write(replacements.get(name));
                    else if (!old.isDirectory()) try (InputStream in = input.getInputStream(old)) { copy(in, out, MAX_EXTRACT); }
                    out.closeEntry();
                }
                for (Map.Entry<String, byte[]> e : replacements.entrySet()) if (!seen.contains(e.getKey())) {
                    out.putNextEntry(new ZipEntry(e.getKey())); out.write(e.getValue()); out.closeEntry();
                }
            }
            replace(temp, dst);
        } finally { temp.delete(); }
    }
    public static void zip(File src, File dst) throws IOException {
        if (dst.exists()) throw new IOException("Destination already exists");
        if (dst.getCanonicalFile().toPath().startsWith(src.getCanonicalFile().toPath())) throw new IOException("Archive cannot be inside its source folder");
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(dst))) { zipTree(src, src.getName(), out); }
        catch (IOException e) { dst.delete(); throw e; }
    }
    private static void zipTree(File f, String name, ZipOutputStream out) throws IOException {
        if (Files.isSymbolicLink(f.toPath())) throw new IOException("Symbolic links are not archived");
        out.putNextEntry(new ZipEntry(name + (f.isDirectory() ? "/" : "")));
        if (f.isFile()) try (InputStream in = new FileInputStream(f)) { copy(in, out, MAX_EXTRACT); }
        out.closeEntry();
        if (f.isDirectory()) { File[] files = f.listFiles(); if (files == null) throw new IOException("Cannot read folder"); for (File c : files) zipTree(c, name + "/" + c.getName(), out); }
    }
    private static final class CountedOutput extends FilterOutputStream {
        long count;
        CountedOutput(OutputStream out) { super(out); }
        public void write(int b) throws IOException { out.write(b); count++; }
        public void write(byte[] b, int off, int len) throws IOException { out.write(b, off, len); count += len; }
    }
    /** Swap a .bak and its original without discarding either version. */
    public static File restoreBackup(File backup) throws IOException {
        if (!backup.getName().endsWith(".bak") || !backup.isFile()) throw new IOException("Choose a .bak file");
        File original = new File(backup.getPath().substring(0, backup.getPath().length()-4));
        if (!original.exists()) { Files.move(backup.toPath(), original.toPath()); return original; }
        if (!original.isFile()) throw new IOException("Original path is a directory");
        File temp = File.createTempFile(".swap-", ".tmp", backup.getAbsoluteFile().getParentFile());
        temp.delete(); boolean movedOriginal=false, movedBackup=false;
        try {
            Files.move(original.toPath(), temp.toPath()); movedOriginal=true;
            Files.move(backup.toPath(), original.toPath()); movedBackup=true;
            Files.move(temp.toPath(), backup.toPath());
        } catch (IOException error) {
            try { if(movedBackup)Files.move(original.toPath(),backup.toPath()); if(movedOriginal)Files.move(temp.toPath(),original.toPath()); }
            catch(IOException recovery){error.addSuppressed(recovery);}
            throw error;
        }
        return original;
    }
    /** Preserve older backups too; an unsuccessful commit leaves the source intact. */
    public static File commitWithBackup(File prepared, File original) throws IOException {
        File backup = new File(original+".bak");
        if(backup.exists()) Files.move(backup.toPath(),new File(original+".bak."+UUID.randomUUID()).toPath());
        Files.copy(original.toPath(),backup.toPath());
        replace(prepared,original);return backup;
    }
    public static String sha256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(f)) { byte[] b = new byte[65536]; int n; while ((n = in.read(b)) != -1) md.update(b, 0, n); }
        StringBuilder s = new StringBuilder(); for (byte b : md.digest()) s.append(String.format("%02x", b & 255)); return s.toString();
    }
}
