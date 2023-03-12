package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.ChaCha20;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class EncryptedConnection {

    private final boolean fastConnect;

    private final SecretKey key;
    private final byte[] keyAdd;

    private final Socket socket;

    private Map<String, Object> headers;

    public EncryptedConnection(Socket socket, SecretKey key, byte[] keyAdd, boolean server, boolean fastConnect) {
        this.fastConnect = fastConnect;
        this.socket = socket;
        this.key = key;
        this.keyAdd = keyAdd;
        this.headers = new HashMap<>();
        try {
            if (server) this.headers = (Map<String, Object>) receive().getObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void send(byte[] bytes) throws Exception {
        byte[] encrypted;
        if (fastConnect) {
            encrypted = ChaCha20.encrypt(bytes, key, keyAdd, 1);
        } else {
            encrypted = AES.encrypt(bytes, key, keyAdd);
        }
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeInt(encrypted.length);
        out.write(encrypted);
        out.flush();
    }

    public void send(Packet<?> packet) throws Exception {
        send(packet.serialize());
    }

    protected Packet<?> receive() throws Exception {
        socket.setSoTimeout(Integer.MAX_VALUE);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        int length = in.readInt();
        byte[] bytes = in.readNBytes(length);
        if (fastConnect)
            return Packet.deserialize(ChaCha20.decrypt(bytes, key, keyAdd, 1));
        return Packet.deserialize(AES.decrypt(bytes, key, keyAdd));
    }

    public Socket getSocket() {
        return socket;
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected();
    }

    public Map<String, Object> getHeaders() {
        return headers;
    }

    public Object getHeader(String key) {
        return headers.get(key);
    }

}
