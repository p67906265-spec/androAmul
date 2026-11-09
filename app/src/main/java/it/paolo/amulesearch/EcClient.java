package it.paolo.amulesearch;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Inflater;

/**
 * Client minimale del protocollo EC (External Connections) di aMule.
 * Supporta solo: autenticazione con salt, avvio/stop ricerca, lettura risultati.
 * Numeri sempre in formato "piano" (nessuna negoziazione zlib / UTF8 numbers).
 */
public class EcClient {

    // Opcode
    static final int OP_AUTH_REQ = 0x02;
    static final int OP_AUTH_FAIL = 0x03;
    static final int OP_AUTH_OK = 0x04;
    static final int OP_FAILED = 0x05;
    static final int OP_STRINGS = 0x06;
    static final int OP_SEARCH_START = 0x26;
    static final int OP_SEARCH_STOP = 0x27;
    static final int OP_SEARCH_RESULTS = 0x28;
    static final int OP_SEARCH_PROGRESS = 0x29;
    static final int OP_AUTH_SALT = 0x4F;
    static final int OP_AUTH_PASSWD = 0x50;

    // Tag
    static final int TAG_STRING = 0x0000;
    static final int TAG_PASSWD_HASH = 0x0001;
    static final int TAG_PROTOCOL_VERSION = 0x0002;
    static final int TAG_PASSWD_SALT = 0x000B;
    static final int TAG_CLIENT_NAME = 0x0100;
    static final int TAG_CLIENT_VERSION = 0x0101;
    static final int TAG_SERVER_VERSION = 0x050B;
    static final int TAG_PARTFILE_NAME = 0x0301;
    static final int TAG_PARTFILE_SIZE_FULL = 0x0303;
    static final int TAG_PARTFILE_SOURCE_COUNT = 0x030A;
    static final int TAG_PARTFILE_SOURCE_COUNT_XFER = 0x030D;
    static final int TAG_PARTFILE_HASH = 0x031E;
    static final int TAG_SEARCHFILE = 0x0700;
    static final int TAG_SEARCH_TYPE = 0x0701;
    static final int TAG_SEARCH_NAME = 0x0702;
    static final int TAG_SEARCH_MIN_SIZE = 0x0703;
    static final int TAG_SEARCH_MAX_SIZE = 0x0704;
    static final int TAG_SEARCH_FILE_TYPE = 0x0705;
    static final int TAG_SEARCH_EXTENSION = 0x0706;
    static final int TAG_SEARCH_AVAILABILITY = 0x0707;
    static final int TAG_SEARCH_STATUS = 0x0708;

    static final int PROTOCOL_VERSION = 0x0204;

    // Tipi di tag
    static final int T_CUSTOM = 1;
    static final int T_UINT8 = 2;
    static final int T_UINT16 = 3;
    static final int T_UINT32 = 4;
    static final int T_UINT64 = 5;
    static final int T_STRING = 6;
    static final int T_DOUBLE = 7;
    static final int T_IPV4 = 8;
    static final int T_HASH16 = 9;

    public static final int SEARCH_LOCAL = 0;
    public static final int SEARCH_GLOBAL = 1;
    public static final int SEARCH_KAD = 2;

    /** Tag letto dal socket. */
    public static class Tag {
        public int name;
        public int type;
        public byte[] data = new byte[0];
        public List<Tag> children = new ArrayList<>();

        public long asLong() {
            long v = 0;
            for (byte b : data) v = (v << 8) | (b & 0xFF);
            return v;
        }

        public String asString() {
            int len = data.length;
            if (len > 0 && data[len - 1] == 0) len--;
            return new String(data, 0, len, StandardCharsets.UTF_8);
        }

        public String asHex() {
            StringBuilder sb = new StringBuilder();
            for (byte b : data) sb.append(String.format("%02x", b & 0xFF));
            return sb.toString();
        }

        public Tag child(int n) {
            for (Tag t : children) if (t.name == n) return t;
            return null;
        }
    }

    /** Pacchetto letto dal socket. */
    public static class Packet {
        public int opcode;
        public List<Tag> tags = new ArrayList<>();

        public Tag tag(int n) {
            for (Tag t : tags) if (t.name == n) return t;
            return null;
        }
    }

    /** Risultato di ricerca. */
    public static class Result {
        public String name = "";
        public long size;
        public long sources;
        public long complete;
        public String hash = "";
    }

    private Socket socket;
    private InputStream in;
    private OutputStream out;

    // ---------------------------------------------------------------- connessione

    public String connect(String host, int port, String password) throws IOException {
        socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), 5000);
        socket.setSoTimeout(15000);
        in = socket.getInputStream();
        out = socket.getOutputStream();

        // 1) AUTH_REQ
        List<byte[]> tags = new ArrayList<>();
        tags.add(tagString(TAG_CLIENT_NAME, "AmuleSearch"));
        tags.add(tagString(TAG_CLIENT_VERSION, "1.0"));
        tags.add(tagInt(TAG_PROTOCOL_VERSION, T_UINT16, PROTOCOL_VERSION, 2));
        sendPacket(OP_AUTH_REQ, tags);

        Packet salt = readPacket();
        if (salt.opcode == OP_AUTH_FAIL) {
            throw new IOException("Autenticazione rifiutata: " + firstString(salt));
        }
        if (salt.opcode != OP_AUTH_SALT || salt.tag(TAG_PASSWD_SALT) == null) {
            throw new IOException("Risposta inattesa dal server (opcode " + salt.opcode + ")");
        }
        long saltValue = salt.tag(TAG_PASSWD_SALT).asLong();

        // 2) AUTH_PASSWD = MD5( md5hex(password) + md5hex(hex(salt) maiuscolo) )
        String passMd5 = md5Hex(password.getBytes(StandardCharsets.UTF_8)).toLowerCase();
        String saltStr = Long.toHexString(saltValue).toUpperCase();
        String saltHash = md5Hex(saltStr.getBytes(StandardCharsets.UTF_8));
        byte[] finalHash = md5Raw((passMd5 + saltHash).getBytes(StandardCharsets.UTF_8));

        List<byte[]> t2 = new ArrayList<>();
        t2.add(tagRaw(TAG_PASSWD_HASH, T_HASH16, finalHash));
        sendPacket(OP_AUTH_PASSWD, t2);

        Packet ok = readPacket();
        if (ok.opcode == OP_AUTH_OK) {
            Tag v = ok.tag(TAG_SERVER_VERSION);
            return v != null ? v.asString() : "";
        }
        throw new IOException("Password errata o accesso negato");
    }

    public void close() {
        try {
            if (socket != null) socket.close();
        } catch (IOException ignored) {
        }
    }

    // ---------------------------------------------------------------- ricerca

    public void startSearch(int searchType, String text, String fileType, String ext,
                            long availability, long minSize, long maxSize) throws IOException {
        List<byte[]> children = new ArrayList<>();
        children.add(tagString(TAG_SEARCH_NAME, text));
        children.add(tagString(TAG_SEARCH_FILE_TYPE, fileType == null ? "" : fileType));
        if (ext != null && !ext.isEmpty()) children.add(tagString(TAG_SEARCH_EXTENSION, ext));
        if (availability > 0) children.add(tagInt(TAG_SEARCH_AVAILABILITY, T_UINT32, availability, 4));
        if (minSize > 0) children.add(tagInt(TAG_SEARCH_MIN_SIZE, T_UINT64, minSize, 8));
        if (maxSize > 0) children.add(tagInt(TAG_SEARCH_MAX_SIZE, T_UINT64, maxSize, 8));

        List<byte[]> top = new ArrayList<>();
        top.add(tagWithChildren(TAG_SEARCH_TYPE, T_UINT8, new byte[]{(byte) searchType}, children));
        sendPacket(OP_SEARCH_START, top);

        Packet reply = readPacket();
        if (reply.opcode == OP_FAILED) {
            throw new IOException(firstString(reply));
        }
        // OP_STRINGS = ricerca avviata; qualsiasi errore arriva come OP_FAILED
    }

    public void stopSearch() throws IOException {
        sendPacket(OP_SEARCH_STOP, new ArrayList<byte[]>());
        readPacket();
    }

    /** Percentuale 0..100, 0xFFFE = Kad finita, 0 = nessuna ricerca / Kad in corso. */
    public long progress() throws IOException {
        sendPacket(OP_SEARCH_PROGRESS, new ArrayList<byte[]>());
        Packet p = readPacket();
        Tag t = p.tag(TAG_SEARCH_STATUS);
        return t == null ? 0 : t.asLong();
    }

    public List<Result> results() throws IOException {
        sendPacket(OP_SEARCH_RESULTS, new ArrayList<byte[]>());
        Packet p = readPacket();
        List<Result> list = new ArrayList<>();
        for (Tag t : p.tags) {
            if (t.name != TAG_SEARCHFILE) continue;
            Result r = new Result();
            Tag n = t.child(TAG_PARTFILE_NAME);
            Tag s = t.child(TAG_PARTFILE_SIZE_FULL);
            Tag src = t.child(TAG_PARTFILE_SOURCE_COUNT);
            Tag cmp = t.child(TAG_PARTFILE_SOURCE_COUNT_XFER);
            Tag h = t.child(TAG_PARTFILE_HASH);
            if (n == null) continue; // aggiornamento parziale senza nome
            r.name = n.asString();
            if (s != null) r.size = s.asLong();
            if (src != null) r.sources = src.asLong();
            if (cmp != null) r.complete = cmp.asLong();
            if (h != null) r.hash = h.asHex();
            list.add(r);
        }
        return list;
    }

    // ---------------------------------------------------------------- codifica

    private static String firstString(Packet p) {
        for (Tag t : p.tags) {
            if (t.type == T_STRING) return t.asString();
        }
        return "";
    }

    static byte[] tagString(int name, String value) {
        byte[] b = value.getBytes(StandardCharsets.UTF_8);
        byte[] d = new byte[b.length + 1];
        System.arraycopy(b, 0, d, 0, b.length);
        return tagRaw(name, T_STRING, d);
    }

    static byte[] tagInt(int name, int type, long value, int size) {
        byte[] d = new byte[size];
        for (int i = size - 1; i >= 0; i--) {
            d[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return tagRaw(name, type, d);
    }

    static byte[] tagRaw(int name, int type, byte[] data) {
        return tagWithChildren(name, type, data, new ArrayList<byte[]>());
    }

    static byte[] tagWithChildren(int name, int type, byte[] data, List<byte[]> children) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int childrenLen = 0;
        if (!children.isEmpty()) {
            body.write((children.size() >> 8) & 0xFF);
            body.write(children.size() & 0xFF);
            childrenLen += 2;
            for (byte[] c : children) {
                body.write(c, 0, c.length);
                childrenLen += c.length;
            }
        }
        body.write(data, 0, data.length);
        // la lunghezza dichiarata include i figli (compreso il contatore) e i dati
        int totalLen = childrenLen + data.length;

        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int n = (name << 1) | (children.isEmpty() ? 0 : 1);
        o.write((n >> 8) & 0xFF);
        o.write(n & 0xFF);
        o.write(type);
        o.write((totalLen >> 24) & 0xFF);
        o.write((totalLen >> 16) & 0xFF);
        o.write((totalLen >> 8) & 0xFF);
        o.write(totalLen & 0xFF);
        byte[] bb = body.toByteArray();
        o.write(bb, 0, bb.length);
        return o.toByteArray();
    }

    private void sendPacket(int opcode, List<byte[]> tags) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(opcode);
        body.write((tags.size() >> 8) & 0xFF);
        body.write(tags.size() & 0xFF);
        for (byte[] t : tags) body.write(t, 0, t.length);
        byte[] b = body.toByteArray();

        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int flags = 0x20; // nessuna compressione, numeri piani
        writeInt(o, flags);
        writeInt(o, b.length);
        o.write(b, 0, b.length);
        out.write(o.toByteArray());
        out.flush();
    }

    private static void writeInt(ByteArrayOutputStream o, int v) {
        o.write((v >> 24) & 0xFF);
        o.write((v >> 16) & 0xFF);
        o.write((v >> 8) & 0xFF);
        o.write(v & 0xFF);
    }

    // ---------------------------------------------------------------- decodifica

    private Packet readPacket() throws IOException {
        DataInputStream d = new DataInputStream(in);
        int flags = d.readInt();
        int len = d.readInt();
        if (len < 0 || len > 64 * 1024 * 1024) throw new IOException("Pacchetto non valido");
        byte[] body = new byte[len];
        d.readFully(body);

        if ((flags & 0x01) != 0) { // zlib
            body = inflate(body);
        }
        if ((flags & 0x02) != 0) {
            throw new IOException("Formato numeri UTF8 non supportato");
        }
        Cursor c = new Cursor(body);
        Packet p = new Packet();
        p.opcode = c.u8();
        int count = c.u16();
        for (int i = 0; i < count; i++) p.tags.add(readTag(c));
        return p;
    }

    private static Tag readTag(Cursor c) throws IOException {
        Tag t = new Tag();
        int n = c.u16();
        t.name = n >> 1;
        boolean hasChildren = (n & 1) != 0;
        t.type = c.u8();
        long len = c.u32();
        int start = c.pos;
        if (hasChildren) {
            int count = c.u16();
            for (int i = 0; i < count; i++) t.children.add(readTag(c));
        }
        long dataLen = len - (c.pos - start);
        if (dataLen < 0 || dataLen > c.remaining()) throw new IOException("Tag non valido");
        t.data = c.bytes((int) dataLen);
        return t;
    }

    private static byte[] inflate(byte[] src) throws IOException {
        try {
            Inflater inf = new Inflater();
            inf.setInput(src);
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                o.write(buf, 0, n);
            }
            inf.end();
            return o.toByteArray();
        } catch (Exception e) {
            throw new IOException("Errore di decompressione");
        }
    }

    private static class Cursor {
        final byte[] b;
        int pos = 0;

        Cursor(byte[] b) {
            this.b = b;
        }

        int remaining() {
            return b.length - pos;
        }

        void need(int n) throws IOException {
            if (remaining() < n) throw new IOException("Dati troncati");
        }

        int u8() throws IOException {
            need(1);
            return b[pos++] & 0xFF;
        }

        int u16() throws IOException {
            need(2);
            int v = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2;
            return v;
        }

        long u32() throws IOException {
            need(4);
            long v = ((long) (b[pos] & 0xFF) << 24) | ((b[pos + 1] & 0xFF) << 16)
                    | ((b[pos + 2] & 0xFF) << 8) | (b[pos + 3] & 0xFF);
            pos += 4;
            return v;
        }

        byte[] bytes(int n) throws IOException {
            need(n);
            byte[] r = new byte[n];
            System.arraycopy(b, pos, r, 0, n);
            pos += n;
            return r;
        }
    }

    // ---------------------------------------------------------------- hash

    static byte[] md5Raw(byte[] in) {
        try {
            return MessageDigest.getInstance("MD5").digest(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static String md5Hex(byte[] in) {
        byte[] d = md5Raw(in);
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }
}
