import de.pterocloud.encryptedconnection.EncryptedConnection;
import de.pterocloud.encryptedconnection.EncryptedServer;
import de.pterocloud.encryptedconnection.Packet;
import de.pterocloud.encryptedconnection.listener.ServerListener;

import java.net.Socket;

public class TestServer {

    public static void main(String[] args) throws Exception {
        long start = System.currentTimeMillis();

        EncryptedServer server = new EncryptedServer(62419);
        server.listener(new ServerListener() {

            @Override
            public boolean onPreEncrypt(Socket socket) {
                System.out.println("[Server] Client pre-encrypting from " + socket.getInetAddress().getHostAddress());
                return true;
            }

            @Override
            public boolean onPreConnect(EncryptedConnection connection) {
                System.out.println("[Server] Client connecting from " + connection.getSocket().getInetAddress().getHostAddress());
                System.out.println("(headers 01) A: " + connection.getHeader("Test-A"));
                System.out.println("(headers 01) B: " + connection.getHeader("Test-B"));
                System.out.println("(headers 01) C: " + connection.getHeader("Test-C"));
                return false;
            }

            @Override
            public void onPostConnect(EncryptedConnection connection) {
                System.out.println("[Server] Client connected from " + connection.getSocket().getInetAddress().getHostAddress());
                System.out.println("(headers 02) A: " + connection.getHeader("Test-A"));
                System.out.println("(headers 02) B: " + connection.getHeader("Test-B"));
                System.out.println("(headers 02) C: " + connection.getHeader("Test-C"));
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
