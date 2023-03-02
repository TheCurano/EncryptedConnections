package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.RSA;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class EncryptedServer {

    private final int port;

    private ServerListener listener;

    private ServerSocket server = null;

    private final ArrayList<EncryptedConnection> encryptedConnections = new ArrayList<>();

    private final Thread serverThread = new Thread(() -> {
        while (server != null && !server.isClosed()) {
            try {
                Socket socket = server.accept();
                if (!listener.onPreConnect(socket)) {
                    socket.close();
                    continue;
                }
                Thread connectionThread = new Thread(() -> {
                    try {
                        Packet packet = Packet.deserialize(receive(socket));
                        PublicKey publicKey = (PublicKey) packet.getObject();
                        SecretKey aes = AES.generateKey();
                        byte[] iv = AES.generateIV();

                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        ObjectOutputStream dataOutput = new ObjectOutputStream(outputStream);
                        dataOutput.writeObject(aes);
                        dataOutput.close();

                        byte[] aesKeyEncrypted = RSA.encrypt(publicKey, Base64.getEncoder().encode(outputStream.toByteArray()));
                        Packet aesPacket = new Packet(Base64.getEncoder().encodeToString(aesKeyEncrypted), (byte) 0);

                        byte[] ivEncrypted = RSA.encrypt(publicKey, iv);
                        Packet ivPacket = new Packet(Base64.getEncoder().encodeToString(ivEncrypted), (byte) 0);

                        send(socket, aesPacket.serialize());
                        send(socket, ivPacket.serialize());
                        // EncryptedConnection encryptedConnection = new EncryptedConnection(socket, this, aes, iv, publicKey);
                        EncryptedConnection encryptedConnection = new EncryptedConnection(socket, null, aes, iv);
                        encryptedConnections.add(encryptedConnection);
                        listener.onPostConnect(encryptedConnection.getClient(), encryptedConnection);
                        try {
                            while (socket.isConnected()) {
                                Packet receivedPacket = encryptedConnection.receive();
                                listener.onPacketReceived(encryptedConnection, receivedPacket);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } catch (IOException | ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                });
                connectionThread.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
            encryptedConnections.removeIf(connection -> !connection.getSocket().isConnected());
        }
    });

    public EncryptedServer(int port) {
        this.port = port;
        this.listener = new ServerListener() {
        };
    }

    public EncryptedServer start() throws IOException {
        server = new ServerSocket(port);
        startServerThread();
        return this;
    }

    public void stop() {
        try {
            server.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public EncryptedServer listener(ServerListener listener) {
        this.listener = listener;
        return this;
    }

    private void startServerThread() {
        if (!serverThread.isAlive()) serverThread.start();
    }

    protected void send(Socket socket, byte[] bytes) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(Base64.getEncoder().encodeToString(bytes));
        out.flush();
        //out.close();
    }

    protected byte[] receive(Socket socket) throws IOException {
        socket.setSoTimeout(60000);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        byte[] bytes = Base64.getDecoder().decode(in.readUTF());
        //in.close();
        return bytes;
    }

    public List<EncryptedConnection> getEncryptedConnections() {
        return encryptedConnections;
    }

}
