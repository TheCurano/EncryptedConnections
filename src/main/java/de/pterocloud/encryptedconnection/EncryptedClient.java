package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.RSA;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public class EncryptedClient {

    protected KeyPair rsa = RSA.generateRSAKey(4096);
    protected String host;
    protected int port;
    protected Socket socket = null;
    protected EncryptedConnection encryptedConnection = null;

    public EncryptedClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    protected void send(byte[] bytes) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(new String(bytes, StandardCharsets.UTF_8));
        out.flush();
        //out.close();
    }

    protected byte[] receive() throws IOException {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = in.readUTF().getBytes();
        //in.close();
        return bytes;
    }

    public EncryptedClient connect() throws IOException, ClassNotFoundException {
        socket = new Socket(host, port);
        socket.setKeepAlive(true);
        send(new Packet(rsa.getPublic(), (byte) 0).serialize());
        Packet sshKey = Packet.deserialize(RSA.decrypt(rsa.getPrivate(), receive()));
        Packet iv = Packet.deserialize(RSA.decrypt(rsa.getPrivate(), receive()));
        if (sshKey.getType() != (byte) 0 && iv.getType() != (byte) 0) {
            throw new RuntimeException("Invalid init packets.");
        }
        encryptedConnection = new EncryptedConnection(socket, this, (SecretKey) sshKey.getObject(), (byte[]) iv.getObject());
        return this;
    }

    public EncryptedConnection getEncryptedConnection() {
        return encryptedConnection;
    }

    public Socket getSocket() {
        return socket;
    }

}
