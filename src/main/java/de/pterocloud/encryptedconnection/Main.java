package de.pterocloud.encryptedconnection;

public class Main {

    public static void main(String[] args) {
        try {
            EncryptedServer server = new EncryptedServer(62411);
            server.start();

            EncryptedClient client01 = new EncryptedClient("0.0.0.0", 62411);
            client01.connect();
            client01.getEncryptedConnection().setPacketListener(new ServerListener((encryptedConnection, packet) -> {
                System.out.println("Client01: " + packet.getType());
            }));
            for (EncryptedConnection connection : server.getEncryptedConnections()) {
                connection.setPacketListener(new ServerListener((encryptedConnection, packet) -> {
                    System.out.println("Server: " + packet.getType());
                    System.out.println("String: " + ((String) packet.getObject()));
                }));
            }
            Packet packet = new Packet("TEST");
            client01.getEncryptedConnection().send(packet);
            if (client01.getEncryptedConnection().isConnected()) {
                System.out.println("Nice shit");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        Thread.currentThread().stop();
    }

}
