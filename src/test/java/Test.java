import de.pterocloud.encryptedconnection.EncryptedClient;
import de.pterocloud.encryptedconnection.EncryptedConnection;
import de.pterocloud.encryptedconnection.EncryptedServer;
import de.pterocloud.encryptedconnection.Packet;
import de.pterocloud.encryptedconnection.listener.ClientListener;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import java.net.Socket;

public class Test {

    public static void main(String[] args) {

        try {
            EncryptedServer server = new EncryptedServer(62411);
            server.start().listener(new ServerListener() {
                @Override
                public void onPacketReceived(EncryptedConnection connection, Packet<?> packet) {
                    System.out.println("[Server] Received packet: " + packet.getObject());
                }

                @Override
                public boolean onPreConnect(Socket socket) {
                    System.out.println("[Server] PreConnect");
                    return true;
                }

                @Override
                public void onPostConnect(EncryptedClient client, EncryptedConnection connection) {
                    System.out.println("[Server] PostConnect");
                    try {
                        connection.send(new Packet<>("TEST"));
                    } catch (Exception exception) {
                        throw new RuntimeException(exception);
                    }
                }
            });

            EncryptedClient client01 = new EncryptedClient("0.0.0.0", 62411);
            client01.connect();
            client01.getEncryptedConnection().listener(new ClientListener() {
                @Override
                public void onPacketReceived(Packet<?> packet) {
                    System.out.println("[Client] Received packet: " + packet.getObject());
                }
            });

            client01.getEncryptedConnection().send(new Packet<>("TEST"));
            if (client01.getEncryptedConnection().isConnected()) {
                System.out.println("[Server] Connection established");
            }
            server.getEncryptedConnections().forEach(con -> {
                try {
                    con.send(new Packet<>("Big baba boom"));
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });

        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

}
