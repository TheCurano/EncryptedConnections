import de.pterocloud.encryptedconnection.EncryptedClient;
import de.pterocloud.encryptedconnection.EncryptedConnection;
import de.pterocloud.encryptedconnection.EncryptedServer;
import de.pterocloud.encryptedconnection.Packet;
import de.pterocloud.encryptedconnection.listener.ClientListener;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import java.net.Socket;

public class Test {

    public static void main(String[] args) {
        final int[] succeededActions = {0};
        final long[] start = {System.currentTimeMillis()};

        try {
            EncryptedServer server = new EncryptedServer(62411);
            server.start().listener(new ServerListener() {
                @Override
                public void onPacketReceived(EncryptedConnection connection, Packet<?> packet) {
                    succeededActions[0]++;
                    System.out.println("[Server] Received packet: " + packet.getObject());
                    if (succeededActions[0] == 2) start[0] = System.currentTimeMillis();
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
                        connection.send(new Packet<>("TEST (to client)"));
                    } catch (Exception exception) {
                        throw new RuntimeException(exception);
                    }
                }
            });

            EncryptedClient client = new EncryptedClient("0.0.0.0", 62411);
            client.connect();
            client.listener(new ClientListener() {
                @Override
                public void onPacketReceived(Packet<?> packet) {
                    System.out.println("[Client] Received packet: " + packet.getObject());
                    succeededActions[0]++;
                }
            });
            if (client.getEncryptedConnection().isConnected()) {
                System.out.println("[Server] Connection established");
            }

            client.getEncryptedConnection().send(new Packet<>("TEST (to server)"));

            Thread.sleep(300); // Wait for the packets to be sent

            if (succeededActions[0] == 2) {
                System.out.println("Test succeeded in (" + (System.currentTimeMillis() - start[0]) + "ms)");
            } else {
                System.out.println("Test failed in (" + (System.currentTimeMillis() - start[0]) + "ms)");
            }

        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

}
