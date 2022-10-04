package de.pterocloud.encryptedconnection;

import java.util.function.BiConsumer;

public class PacketListener {

    private BiConsumer<EncryptedConnection, Packet> consumer;

    public PacketListener(BiConsumer<EncryptedConnection, Packet> consumer) {
        this.consumer = consumer;
    }

    public BiConsumer<EncryptedConnection, Packet> getConsumer() {
        return consumer;
    }

    public PacketListener setConsumer(BiConsumer<EncryptedConnection, Packet> consumer) {
        this.consumer = consumer;
        return this;
    }

    public void accept(EncryptedConnection connection, Packet packet) {
        consumer.accept(connection, packet);
    }

}
