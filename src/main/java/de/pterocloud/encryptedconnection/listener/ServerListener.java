package de.pterocloud.encryptedconnection.listener;

import de.pterocloud.encryptedconnection.EncryptedConnection;
import de.pterocloud.encryptedconnection.Packet;

import java.net.Socket;

public interface ServerListener {

    /**
     * Triggered before the connection is encrypted
     *
     * @param socket the socket
     * @return whether the connection should be accepted
     */
    default boolean onPreEncrypt(Socket socket) {
        return true;
    }

    /**
     * Triggered before the connection is accepted
     *
     * @param connection the connection
     * @return whether the connection should be accepted
     */
    default boolean onPreConnect(EncryptedConnection connection) {
        return true;
    }

    /**
     * Triggered after the connection is encrypted
     *
     * @param connection the connection
     */
    default void onPostConnect(EncryptedConnection connection) {

    }

    /**
     * Triggered when the connection is disconnected
     *
     * @param connection the connection
     */
    default void onDisconnect(EncryptedConnection connection) {

    }

    /**
     * Triggered when a packet is received
     *
     * @param connection the connection
     * @param packet     the packet
     */
    default void onPacketReceived(EncryptedConnection connection, Packet<?> packet) {

    }

}
