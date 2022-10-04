package de.pterocloud.encryptedconnection;

public class Main {

    public static void main(String[] args) {
        try {
            EncryptedServer server = new EncryptedServer(62411);
            server.start();

            EncryptedClient client01 = new EncryptedClient("0.0.0.0", 62411);
            client01.connect();
            client01.getEncryptedConnection().setPacketListener(new PacketListener((encryptedConnection, packet) -> {
                System.out.println("Client01: " + packet.getType());
            }));
            Packet packet = new Packet("TEST");
            client01.send(packet.serialize());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
