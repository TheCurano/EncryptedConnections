package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.RSA;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;

public class EncryptedServer {

    private int port = 9119;
    private ServerSocket server = null;
    private ArrayList<EncryptedConnection> encryptedConnections = new ArrayList<>();
    private Thread connectionThread = new Thread(() -> {
        while (server != null && !server.isClosed()) {
            try {
                Socket socket = server.accept();
                System.out.println("New connection");
                Thread connectionThread = new Thread(() -> {
                    try {
                        Packet packet = Packet.deserialize(receive(socket));
                        PublicKey publicKey = (PublicKey) packet.getObject();
                        SecretKey aes = AES.generateKey();
                        byte[] iv = AES.getIV();
                        Packet aesPacket = new Packet(aes, (byte) 0);
                        Packet ivPacket = new Packet(iv, (byte) 0);
                        send(socket, RSA.encrypt(publicKey, aesPacket.serialize()));
                        send(socket, RSA.encrypt(publicKey, ivPacket.serialize()));
                        encryptedConnections.add(new EncryptedConnection(socket, this, aes, iv, publicKey));
                    } catch (IOException | ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                });
                connectionThread.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    });

    public EncryptedServer(int port) {
        this.port = port;
    }

    public EncryptedServer start() throws IOException {
        server = new ServerSocket(port);
        startConnectionThread();
        return this;
    }

    private void startConnectionThread() {
        if (!connectionThread.isAlive()) connectionThread.start();
    }

    public void stop() {

    }

    protected void send(Socket socket, byte[] bytes) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(new String(bytes, StandardCharsets.UTF_8));
        out.flush();
        out.close();
    }

    protected byte[] receive(Socket socket) throws IOException {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = in.readUTF().getBytes();
        in.close();
        return bytes;
    }

}
