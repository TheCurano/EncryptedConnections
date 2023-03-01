package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.listener.ClientListener;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.PublicKey;
import java.util.Base64;

public class EncryptedConnection {

    //private PublicKey publicKey = null;
    private EncryptedClient client = null;
    //private EncryptedServer server = null;
    private final SecretKey aes;
    private final byte[] iv;
    private final Socket socket;
    private ClientListener listener = new ClientListener() {
    };

    public EncryptedConnection(Socket socket, EncryptedClient client, SecretKey aes, byte[] iv) {
        this.client = client;
        this.socket = socket;
        this.aes = aes;
        this.iv = iv;
        setupListener();
    }

//    public EncryptedConnection(Socket socket, EncryptedServer server, SecretKey aes, byte[] iv, PublicKey publicKey) {
//        this.server = server;
//        this.socket = socket;
//        this.aes = aes;
//        this.iv = iv;
//        this.publicKey = publicKey;
//        setupListener();
//    }

    private void setupListener() {
        Thread packetListener = new Thread(() -> {
            while (socket.isConnected()) {
                try {
                    getListener().onPacketReceived(receive());
                } catch (Exception e) {
                    if (e instanceof SocketTimeoutException) {
                        if (isConnected()) {
                            continue;
                        } else {
                            throw new RuntimeException(e);
                        }
                    }
                    e.printStackTrace();
                }
            }
        });
        packetListener.start();
    }

    public void send(byte[] bytes) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        byte[] encrypted = AES.encrypt(bytes, aes, iv);
        out.writeUTF(Base64.getEncoder().encodeToString(encrypted));
        out.flush();
    }

    public void send(Packet packet) throws Exception {
        send(packet.serialize());
    }

    protected Packet receive() throws Exception {
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

    public EncryptedConnection listener(ClientListener listener) {
        this.listener = listener;
        return this;
    }

    public ClientListener getListener() {
        return listener;
    }

}
