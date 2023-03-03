package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

import java.util.Base64;

public class EncryptedConnection {

    private final EncryptedClient client;

    private final SecretKey aes;

    private final byte[] iv;

    private final Socket socket;

    public EncryptedConnection(Socket socket, EncryptedClient client, SecretKey aes, byte[] iv) {
        this.client = client;
        this.socket = socket;
        this.aes = aes;
        this.iv = iv;
    }

    public void send(byte[] bytes) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(Base64.getEncoder().encodeToString(AES.encrypt(bytes, aes, iv)));
        out.flush();
    }

    protected Packet<?> receive() throws Exception {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = Base64.getDecoder().decode(in.readUTF());
        return Packet.deserialize(AES.decrypt(bytes, aes, iv));
    }

    public EncryptedClient getClient() {
        return client;
    }

    public Socket getSocket() {
        return socket;
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected();
    }

}
