package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class EncryptedConnection {

    private final SecretKey aes;

    private final byte[] iv;

    private final Socket socket;

    private Map<String, Object> headers;

    public EncryptedConnection(Socket socket, SecretKey aes, byte[] iv, boolean server) {
        this.socket = socket;
        this.aes = aes;
        this.iv = iv;
        this.headers = new HashMap<>();

        try {
            if (server) this.headers = (Map<String, Object>) receive().getObject();
        } catch (Exception ignored) {
            // can happen if it's a server connection
        }
    }

    public void send(byte[] bytes) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(Base64.getEncoder().encodeToString(AES.encrypt(bytes, aes, iv)));
        out.flush();
    }

    protected Packet<?> receive() throws Exception {
        socket.setSoTimeout(Integer.MAX_VALUE);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = Base64.getDecoder().decode(in.readUTF());
        return Packet.deserialize(AES.decrypt(bytes, aes, iv));
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
