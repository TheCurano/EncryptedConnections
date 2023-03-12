package de.pterocloud.encryptedconnection;

import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.ChaCha20;
import de.pterocloud.encryptedconnection.crypto.RSA;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
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
                new Thread(() -> {
                    try {
                        Packet<?> packet = Packet.deserialize(receive(socket));
                        PublicKey publicKey = (PublicKey) packet.getObject();
                        Packet<?> fastConnectionPacket = Packet.deserialize(receive(socket));
                        boolean fastConnection = (boolean) fastConnectionPacket.getObject();
                        EncryptedConnection encryptedConnection = null;
                        if (fastConnection) {
                            SecretKey cha = ChaCha20.generateKey();
                            byte[] nounce = ChaCha20.generateNonce();

                            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                            ObjectOutputStream dataOutput = new ObjectOutputStream(outputStream);
                            dataOutput.writeObject(cha);
                            dataOutput.close();
                            byte[] chaEncrypted = RSA.encrypt(publicKey, Base64.getEncoder().encode(outputStream.toByteArray()));
                            Packet<?> chaPacket = new Packet<>(Base64.getEncoder().encodeToString(chaEncrypted), (byte) 0);

                            byte[] nounceEncrypted = RSA.encrypt(publicKey, nounce);
                            Packet<?> nouncePacket = new Packet<>(Base64.getEncoder().encodeToString(nounceEncrypted), (byte) 0);
                            send(socket, chaPacket.serialize());
                            send(socket, nouncePacket.serialize());
                            encryptedConnection = new EncryptedConnection(socket, cha, nounce, true, fastConnection);
                        } else {
                            SecretKey aes = AES.generateKey();
                            byte[] iv = AES.generateIV();

                            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                            ObjectOutputStream dataOutput = new ObjectOutputStream(outputStream);
                            dataOutput.writeObject(aes);
                            dataOutput.close();

                            byte[] aesKeyEncrypted = RSA.encrypt(publicKey, Base64.getEncoder().encode(outputStream.toByteArray()));
                            Packet<?> aesPacket = new Packet<>(Base64.getEncoder().encodeToString(aesKeyEncrypted), (byte) 0);

                            byte[] ivEncrypted = RSA.encrypt(publicKey, iv);
                            Packet<?> ivPacket = new Packet<>(Base64.getEncoder().encodeToString(ivEncrypted), (byte) 0);

                            send(socket, aesPacket.serialize());
                            send(socket, ivPacket.serialize());
                            encryptedConnection = new EncryptedConnection(socket, aes, iv, true, fastConnection);
                        }
                        encryptedConnections.add(encryptedConnection);
                        listener.onPostConnect(encryptedConnection);
                        while (socket.isConnected()) {
                            try {
                                Packet<?> pv = encryptedConnection.receive();
                                if (!encryptedConnections.contains(encryptedConnection)) break;
                                if (pv.getType() == 1) {
                                    listener.onPacketReceived(encryptedConnection, pv);
                                    encryptedConnections.remove(encryptedConnection);
                                    listener.onDisconnect(encryptedConnection);
                                    break;
                                }
                            } catch (Exception exception) {
                                encryptedConnections.remove(encryptedConnection);
                                listener.onDisconnect(encryptedConnection);
                                if (!(exception instanceof SocketTimeoutException)) {
                                    exception.printStackTrace();
                                }
                                break;
                            }
                        }
                    } catch (Exception exception) {
                        throw new RuntimeException(exception);
                    }
                }).start();
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
    });

    public EncryptedServer(int port) {
        this.port = port;
        this.listener = new ServerListener() {
        };
    }

    public EncryptedServer start() throws IOException {
        server = new ServerSocket(port);
        serverThread.start();
        return this;
    }

    public void stop() {
        try {
            disconnectAll();
            server.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public EncryptedServer listener(ServerListener listener) {
        this.listener = listener;
        return this;
    }

    protected void send(Socket socket, byte[] bytes) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(Base64.getEncoder().encodeToString(bytes));
        out.flush();
    }

    protected byte[] receive(Socket socket) throws IOException {
        socket.setSoTimeout(Integer.MAX_VALUE);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        return Base64.getDecoder().decode(in.readUTF());
    }

    public List<EncryptedConnection> getEncryptedConnections() {
        return encryptedConnections;
    }

    public void disconnectClient(EncryptedConnection encryptedConnection) {
        try {
            encryptedConnection.send(new Packet<>(null, (byte) 1).serialize());
            encryptedConnection.getSocket().close();
        } catch (Exception ignored) {
        }

        encryptedConnections.remove(encryptedConnection);
    }

    public void send(EncryptedConnection client, Packet<?> packet) {
        try {
            if (client.getSocket() == null || !client.getSocket().isConnected())
                throw new SocketTimeoutException("Socket is not connected");
            client.send(packet.serialize());
        } catch (Exception exception) {
            try {
                client.getSocket().close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            listener.onDisconnect(client);
        }
    }

    public void disconnectAll() {
        encryptedConnections.forEach(this::disconnectClient);
    }

}
