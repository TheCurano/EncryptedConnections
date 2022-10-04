package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.RSA;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Base64;

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
        out.writeUTF(Base64.getEncoder().encodeToString(bytes));
        out.flush();
    }

    protected byte[] receive() throws IOException {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());

        return Base64.getDecoder().decode(in.readUTF());
    }

    public EncryptedClient connect() throws IOException, ClassNotFoundException {
        socket = new Socket(host, port);
        socket.setKeepAlive(true);
        send(new Packet(rsa.getPublic(), (byte) 0).serialize());
        Packet aesPacket = Packet.deserialize(receive());
        Packet iv = Packet.deserialize(receive());

        byte[] decryptedAESKey = RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) aesPacket.getObject()));
        ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(decryptedAESKey));
        ObjectInputStream dataInput = new ObjectInputStream(inputStream);
        SecretKey aesKey = (SecretKey) dataInput.readObject();
        dataInput.close();
        aesPacket = new Packet(aesKey, (byte) 0);
        iv = new Packet(RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) iv.getObject())), (byte) 0);
        if (aesPacket.getType() != (byte) 0 && iv.getType() != (byte) 0) {
            throw new RuntimeException("Invalid init packets.");
        }
        encryptedConnection = new EncryptedConnection(socket, this, (SecretKey) aesPacket.getObject(), (byte[]) iv.getObject());
        return this;
    }

    public EncryptedConnection getEncryptedConnection() {
        return encryptedConnection;
    }

    @Deprecated
    public Socket getSocket() {
        return socket;
    }

}
