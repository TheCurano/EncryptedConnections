package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.RSA;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.util.Base64;

public class EncryptedClient {

    protected final KeyPair rsa = RSA.generateRSAKey(4096);

    protected final String host;

    protected final int port;

    protected Socket socket = null;

    protected EncryptedConnection encryptedConnection = null;

    public EncryptedClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /**
     * Not encrypted send
     *
     * @param bytes
     * @throws IOException
     */
    protected void send(byte[] bytes) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(Base64.getEncoder().encodeToString(bytes));
        out.flush();
    }

    /**
     * Not encrypted receive
     *
     * @return byte[]
     * @throws IOException
     */
    protected byte[] receive() throws IOException {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());

        return Base64.getDecoder().decode(in.readUTF());
    }

    /**
     * Connects the client to the encrypted Server
     *
     * @return EncryptedClient
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public EncryptedClient connect() throws IOException, ClassNotFoundException {
        // Connecting
        socket = new Socket(host, port);
        socket.setKeepAlive(true);

        // Sending and receiving required packets for the Encryption
        send(new Packet<>(rsa.getPublic(), (byte) 0).serialize());
        Packet<?> aesPacket = Packet.deserialize(receive());
        Packet<?> iv = Packet.deserialize(receive());

        // Decrypting received packets
        byte[] decryptedAESKey = RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) aesPacket.getObject()));
        ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(decryptedAESKey));
        ObjectInputStream dataInput = new ObjectInputStream(inputStream);
        SecretKey aesKey = (SecretKey) dataInput.readObject();
        dataInput.close();
        aesPacket = new Packet<>(aesKey, (byte) 0);
        iv = new Packet<>(RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) iv.getObject())), (byte) 0);

        if (aesPacket.getType() != (byte) 0 && iv.getType() != (byte) 0) {
            throw new RuntimeException("Invalid init packets.");
        }

        // Creating EncryptedConnection
        encryptedConnection = new EncryptedConnection(socket, this, (SecretKey) aesPacket.getObject(), (byte[]) iv.getObject());
        return this;
    }

    public EncryptedConnection getEncryptedConnection() {
        return encryptedConnection;
    }

    public void disconnect() throws IOException {
        socket.close();
    }

    @Deprecated
    public Socket getSocket() {
        return socket;
    }

}
