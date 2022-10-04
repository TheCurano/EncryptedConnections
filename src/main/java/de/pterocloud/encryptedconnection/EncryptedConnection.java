package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.PublicKey;
import java.util.Base64;

public class EncryptedConnection {

    private PublicKey publicKey = null;
    private EncryptedClient client = null;
    private EncryptedServer server = null;
    private SecretKey aes = null;
    private byte[] iv = null;
    private Socket socket = null;
    private ServerListener packetListener = null;

    public EncryptedConnection(Socket socket, EncryptedClient client, SecretKey aes, byte[] iv) {
        this.client = client;
        this.socket = socket;
        this.aes = aes;
        this.iv = iv;

        Thread packetListener = new Thread(() -> {
            while (socket.isConnected()) {
                try {
                    Packet packet = Packet.deserialize(receive());
                    System.out.println(packet.getType() + "");
                    if (getPacketListener() != null && getPacketListener().getPacketReceived() != null) {
                        getPacketListener().onPacketReceived(this, packet);
                    }
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

    public EncryptedConnection(Socket socket, EncryptedServer server, SecretKey aes, byte[] iv, PublicKey publicKey) {
        this.server = server;
        this.socket = socket;
        this.aes = aes;
        this.iv = iv;
        this.publicKey = publicKey;

        Thread packetListener = new Thread(() -> {
            while (socket.isConnected()) {
                try {
                    Packet packet = Packet.deserialize(receive());
                    System.out.println(packet.getType() + "");
                    if (getPacketListener() != null && getPacketListener().getPacketReceived() != null) {
                        getPacketListener().onPacketReceived(this, packet);
                    }
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

    public byte[] receive() throws Exception {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = Base64.getDecoder().decode(in.readUTF());
        return AES.decrypt(bytes, aes, iv);
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

    public EncryptedConnection setPacketListener(ServerListener packetListener) {
        this.packetListener = packetListener;
        return this;
    }

    public ServerListener getPacketListener() {
        return packetListener;
    }

}
