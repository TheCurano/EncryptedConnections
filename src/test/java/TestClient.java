import de.pterocloud.encryptedconnection.EncryptedClient;
import de.pterocloud.encryptedconnection.Packet;
import de.pterocloud.encryptedconnection.listener.ClientListener;

import java.net.InetSocketAddress;

public class TestClient {

    public static void main(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        EncryptedClient client = new EncryptedClient("0.0.0.0", 62419)
                .listener(new ClientListener() {

                              @Override
                              public void onConnect(InetSocketAddress address) {
                                  System.out.println("[Client] Connected to " + address.getHostString() + ":" + address.getPort());
                              }

                              @Override
                              public void onDisconnect(InetSocketAddress address) {
                                  System.out.println("[Client] Disconnected from " + address.getHostString() + ":" + address.getPort());
                              }

                              @Override
                              public void onPacketReceived(Packet<?> packet) {
                                  System.out.println("[Client] Received packet: " + packet.getObject());
                              }
                          }
                ).connect();
        System.out.println("Started client in " + (System.currentTimeMillis() - start) + "ms");

        client.send(new Packet<>("Test-Packet"));
    }

}
