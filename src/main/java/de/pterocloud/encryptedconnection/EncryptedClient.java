package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.RSA;
import de.pterocloud.encryptedconnection.listener.ClientListener;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.util.Base64;

public class EncryptedClient {

    protected final KeyPair rsa = RSA.generateRSAKey(4096);

    protected final String host;

    protected final int port;

    protected Socket socket;

    protected EncryptedConnection encryptedConnection;

    protected ClientListener listener;

    public EncryptedClient(String host, int port) {
        this.host = host;
        this.port = port;
        this.listener = new ClientListener() {
        };
    }

    /**
     * Not encrypted send
     *
     * @param bytes
     * @throws IOException
     */
    protected void send(byte[] bytes) throws IOException {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF(Base64.getEncoder().encodeToString(bytes));
            out.flush();
        } catch (Exception exception) {
            getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Not encrypted receive
     *
     * @return byte[]
     * @throws IOException
     */
    protected byte[] receive() throws IOException {
        socket.setSoTimeout(60000);
        return Base64.getDecoder().decode(new DataInputStream(socket.getInputStream()).readUTF());
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

        new Thread(() -> {
            while (socket.isConnected()) {
                try {
                    Packet<?> packet = getEncryptedConnection().receive();
                    if (packet.getType() == (byte) 1) {
                        getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
                        socket.close();
                        break;
                    }
                    getListener().onPacketReceived(packet);
                } catch (Exception exception) {
                    if (exception instanceof SocketTimeoutException && getEncryptedConnection().isConnected()) continue;
                    exception.printStackTrace();
                }
            }
        }).start();
        getListener().onConnect(new InetSocketAddress(InetAddress.getByName(host), port));
        return this;
    }

    public EncryptedConnection getEncryptedConnection() {
        return encryptedConnection;
    }

    public void disconnect() throws Exception {
        getEncryptedConnection().send(new Packet<>(null, (byte) 1));
        getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
        socket.close();
    }

    public EncryptedClient listener(ClientListener listener) {
        this.listener = listener;
        return this;
    }

    public ClientListener getListener() {
        return listener;
    }

}
