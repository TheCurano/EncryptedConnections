package de.pterocloud.encryptedconnection;

import java.util.function.BiConsumer;

/**
 * The Listener for the Connection
 * Trigger: PacketReceived
 */
public class ConnectionListener {

    private BiConsumer<EncryptedConnection, Packet> consumer;

    public ConnectionListener(BiConsumer<EncryptedConnection, Packet> consumer) {
        this.consumer = consumer;
    }

    public BiConsumer<EncryptedConnection, Packet> getConsumer() {
        return consumer;
    }

    public ConnectionListener setConsumer(BiConsumer<EncryptedConnection, Packet> consumer) {
        this.consumer = consumer;
        return this;
    }

    public void accept(EncryptedConnection connection, Packet packet) {
        consumer.accept(connection, packet);
    }

}