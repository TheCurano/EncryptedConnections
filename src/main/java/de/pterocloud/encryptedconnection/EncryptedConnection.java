package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class EncryptedConnection {

    private PublicKey publicKey = null;
    private EncryptedClient client = null;
    private EncryptedServer server = null;
    private SecretKey aes = null;
    private byte[] iv = null;
    private Socket socket = null;
    private PacketListener packetListener = null;

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
                    if (getPacketListener() != null && getPacketListener().getConsumer() != null) {
                        getPacketListener().accept(this, packet);
                    }
                } catch (Exception e) {
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
                    if (getPacketListener() != null && getPacketListener().getConsumer() != null) {
                        getPacketListener().accept(this, packet);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        packetListener.start();
    }

    public void send(byte[] bytes) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(new String(AES.encrypt(bytes, aes, iv), StandardCharsets.UTF_8));
        out.flush();
        //out.close();
    }

    public byte[] receive() throws Exception {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = in.readUTF().getBytes();
        //in.close();
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

    public EncryptedConnection setPacketListener(PacketListener packetListener) {
        this.packetListener = packetListener;
        return this;
    }

    public PacketListener getPacketListener() {
        return packetListener;
    }

}
