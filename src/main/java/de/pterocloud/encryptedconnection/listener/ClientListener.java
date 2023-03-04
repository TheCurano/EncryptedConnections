package de.pterocloud.encryptedconnection.listener;

import de.pterocloud.encryptedconnection.Packet;

import java.net.InetSocketAddress;

public interface ClientListener {

    /**
     * Triggered when the client connects to the server
     *
     * @param address the address
     */
    default void onConnect(InetSocketAddress address) {

    }

    /**
     * Triggered when the client disconnects from the server
     *
     * @param address the address
     */
    default void onDisconnect(InetSocketAddress address) {

    }

    /**
     * Triggered when a packet is received
     *
     * @param packet the packet
     */
    default void onPacketReceived(Packet<?> packet) {

    }

}
