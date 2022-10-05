package de.pterocloud.encryptedconnection;

import java.net.Socket;
import java.sql.Connection;
import java.util.function.BiConsumer;

/**
 * The Listener for a entire EncryptedServer
 * Trigger: PacketReceived, PreConnect (not encrypted), PostConnect (encrypted)
 */
public class ServerListener {

    private BiConsumer<EncryptedConnection, Packet> packetReceived;
    private BiConsumer<Socket, Connection> preConnect;
    private BiConsumer<EncryptedClient, EncryptedConnection> postConnect;

    public ServerListener(BiConsumer<EncryptedConnection, Packet> packetReceived) {
        this.packetReceived = packetReceived;
    }

    public ServerListener(BiConsumer<EncryptedConnection, Packet> packetReceived, BiConsumer<Socket, Connection> preConnect) {
        this.packetReceived = packetReceived;
        this.preConnect = preConnect;
    }

    public ServerListener(BiConsumer<EncryptedConnection, Packet> packetReceived, BiConsumer<Socket, Connection> preConnect, BiConsumer<EncryptedClient, EncryptedConnection> postConnect) {
        this.packetReceived = packetReceived;
        this.preConnect = preConnect;
        this.postConnect = postConnect;
    }

    public BiConsumer<EncryptedConnection, Packet> getPacketReceived() {
        return packetReceived;
    }

    public ServerListener setPacketReceived(BiConsumer<EncryptedConnection, Packet> consumer) {
        this.packetReceived = consumer;
        return this;
    }

    protected void onPacketReceived(EncryptedConnection connection, Packet packet) {
        packetReceived.accept(connection, packet);
    }

    public BiConsumer<Socket, Connection> getPreConnect() {
        return preConnect;
    }

    public ServerListener setPreConnect(BiConsumer<Socket, Connection> consumer) {
        this.preConnect = consumer;
        return this;
    }

    protected void onPreConnect(Socket socket, Connection connection) {
        preConnect.accept(socket, connection);
    }

    public BiConsumer<EncryptedClient, EncryptedConnection> getPostConnect() {
        return postConnect;
    }

    public ServerListener setPostConnect(BiConsumer<EncryptedClient, EncryptedConnection> consumer) {
        this.postConnect = consumer;
        return this;
    }

    protected void onPostConnect(EncryptedClient client, EncryptedConnection connection) {
        postConnect.accept(client, connection);
    }

}
