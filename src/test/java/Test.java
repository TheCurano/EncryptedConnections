import de.pterocloud.encryptedconnection.*;
import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.RSA;
import de.pterocloud.encryptedconnection.listener.ClientListener;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

public class Test {

    public static void main(String[] args) {

        try {
            EncryptedServer server = new EncryptedServer(62411);
            server.start();
            server.listener(new ServerListener() {
                @Override
                public void onPacketReceived(EncryptedConnection connection, Packet<?> packet) {
                    System.out.println("[Server] received packet: " + packet.getObject());
                }

                @Override
                public boolean onPreConnect(Socket socket) {
                    System.out.println("[Server] PreConnect");
                    return true;
                }

                @Override
                public void onPostConnect(EncryptedClient client, EncryptedConnection connection) {
                    System.out.println("[Server] PostConnect");
                }
            });

            EncryptedClient client01 = new EncryptedClient("0.0.0.0", 62411);
            client01.connect();
            client01.getEncryptedConnection().listener(new ClientListener() {
                @Override
                public void onPacketReceived(Packet<?> packet) {
                    System.out.println("[Client] received packet: " + packet.getObject());
                }
            });
            Packet<String> packet = new Packet<>("TEST");
            client01.getEncryptedConnection().send(packet);
            if (client01.getEncryptedConnection().isConnected()) {
                System.out.println("[Server] Connection established");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
