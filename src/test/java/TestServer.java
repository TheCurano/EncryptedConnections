import de.pterocloud.encryptedconnection.EncryptedConnection;
import de.pterocloud.encryptedconnection.EncryptedServer;
import de.pterocloud.encryptedconnection.Packet;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import java.net.Socket;

public class TestServer {

    public static void main(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        new EncryptedServer(62419)
                .listener(new ServerListener() {

                    @Override
                    public boolean onPreConnect(Socket socket) {
                        System.out.println("[Server] Client pre-connecting from " + socket.getInetAddress().getHostAddress());
                        return true;
                    }

                    @Override
                    public void onPostConnect(EncryptedConnection connection) {
                        System.out.println("[Server] Client connected from " + connection.getSocket().getInetAddress().getHostAddress());
                        System.out.println("A: " + connection.getHeader("Test-A"));
                        System.out.println("B: " + connection.getHeader("Test-B"));
                        System.out.println("C: " + connection.getHeader("Test-C"));
                    }

                    @Override
                    public void onDisconnect(EncryptedConnection connection) {
                        System.out.println("[Server] Client disconnected from " + connection.getSocket().getInetAddress().getHostAddress());
                    }

                    @Override
                    public void onPacketReceived(EncryptedConnection connection, Packet<?> packet) {
                        System.out.println("[Server] Received packet from " + connection.getSocket().getInetAddress().getHostAddress() + ": " + packet.getObject());
                    }
                }).start();
        System.out.println("Started server in " + (System.currentTimeMillis() - start) + "ms");
    }

}
