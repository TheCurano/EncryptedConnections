package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.RSA;
import de.pterocloud.encryptedconnection.listener.ClientListener;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class EncryptedClient {

    protected final KeyPair rsa = RSA.generateRSAKey(4096);

    protected final String host;

    protected final int port;

    private final Map<String, Object> headers;

    protected Socket socket;

    protected EncryptedConnection encryptedConnection;

    protected ClientListener listener;

    public EncryptedClient(String host, int port) {
        this.headers = new HashMap<>();
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
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(Base64.getEncoder().encodeToString(bytes));
        out.flush();
    }

    public void send(Packet<?> packet) throws IOException {
        try {
            if (socket == null || !socket.isConnected()) {
                throw new SocketTimeoutException("Socket is not connected");
            }
            encryptedConnection.send(packet.serialize());
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
        socket.setSoTimeout(Integer.MAX_VALUE);
        return Base64.getDecoder().decode(new DataInputStream(socket.getInputStream()).readUTF());
    }

    /**
     * Connects the client to the encrypted Server
     *
     * @return EncryptedClient
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public EncryptedClient connect(boolean fastConnection) throws IOException, ClassNotFoundException {
        // Connecting
        socket = new Socket(host, port);
        socket.setKeepAlive(true);
        socket.setSoTimeout(Integer.MAX_VALUE);

        // Sending and receiving required packets for the Encryption
        send(new Packet<>(rsa.getPublic(), (byte) 0).serialize());
        send(new Packet<>(fastConnection, (byte) 0).serialize());
        if (fastConnection) {
            Packet<?> chaPacket = Packet.deserialize(receive());
            Packet<?> nouncePacket = Packet.deserialize(receive());
            byte[] decryptedAESKey = RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) chaPacket.getObject()));
            ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(decryptedAESKey));
            ObjectInputStream dataInput = new ObjectInputStream(inputStream);
            SecretKey chaKey = (SecretKey) dataInput.readObject();
            byte[] nounce = RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) nouncePacket.getObject()));
            encryptedConnection = new EncryptedConnection(socket, chaKey, nounce, false, fastConnection);
            try {
                encryptedConnection.send(new Packet<>(headers, (byte) 11));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            Packet<?> aesPacket = Packet.deserialize(receive());
            Packet<?> ivPacket = Packet.deserialize(receive());

            // Decrypting received packets
            byte[] decryptedAESKey = RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) aesPacket.getObject()));
            ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(decryptedAESKey));
            ObjectInputStream dataInput = new ObjectInputStream(inputStream);
            SecretKey aesKey = (SecretKey) dataInput.readObject();
            dataInput.close();
            aesPacket = new Packet<>(aesKey, (byte) 0);
            byte[] iv = RSA.decrypt(rsa.getPrivate(), Base64.getDecoder().decode((String) ivPacket.getObject()));
            if (aesPacket.getType() != (byte) 0 && ivPacket.getType() != (byte) 0) {
                throw new RuntimeException("Invalid init packets.");
            }
            encryptedConnection = new EncryptedConnection(socket, (SecretKey) aesPacket.getObject(), iv, false, fastConnection);
            try {
                encryptedConnection.send(new Packet<>(headers, (byte) 11));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        // Creating EncryptedConnection

        new Thread(() -> {
            while (socket.isConnected()) {
                try {
                    Packet<?> packet = getEncryptedConnection().receive();
                    if (packet.getType() == (byte) 1) {
                        getListener().onPacketReceived(packet);
                        socket.close();
                        getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
                        break;
                    }
                    getListener().onPacketReceived(packet);
                } catch (Exception exception) {
                    if (exception instanceof SocketTimeoutException && getEncryptedConnection().isConnected()) continue;
                    try {
                        socket.close();
                        getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
                        break;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            try {
                getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
            } catch (UnknownHostException exception) {
                exception.printStackTrace();
            }
        }).start();
        getListener().onConnect(new InetSocketAddress(InetAddress.getByName(host), port));
        return this;
    }

    public EncryptedConnection getEncryptedConnection() {
        return encryptedConnection;
    }

    public void disconnect() throws Exception {
        getEncryptedConnection().send(new Packet<>(null, (byte) 1).serialize());
        getListener().onDisconnect(new InetSocketAddress(InetAddress.getByName(host), port));
        socket.close();
    }

    public EncryptedClient listener(ClientListener listener) {
        this.listener = listener;
        return this;
    }

    public EncryptedClient header(String key, Object value) {
        headers.put(key, value);
        return this;
    }

    public ClientListener getListener() {
        return listener;
    }

}
