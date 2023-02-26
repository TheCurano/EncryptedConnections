package de.pterocloud.encryptedconnection.listener;

import de.pterocloud.encryptedconnection.Packet;

public interface ClientListener {

    /**
     * Triggered when a packet is received
     *
     * @param packet the packet
     */
    default void onPacketReceived(Packet<?> packet) {

    }

}
