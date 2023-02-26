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
            System.out.println("Started time: " + System.currentTimeMillis());
            client01.getEncryptedConnection().send(packet);
            if (client01.getEncryptedConnection().isConnected()) {
                System.out.println("Nice shit");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
//        try {
//            System.out.println("Before: " + System.currentTimeMillis());
//            SecretKey key = AES.generateKey();
//            byte[] iv = AES.generateIV();
//            System.out.println("A: " + System.currentTimeMillis());
//            byte[] encrypted =  AES.encrypt("test".getBytes(StandardCharsets.UTF_8), key, iv);
//            System.out.println("B: " + System.currentTimeMillis());
//            String encrypted_str = Base64.getEncoder().encodeToString(encrypted);
//            System.out.println("C: " + System.currentTimeMillis());
//            byte[] decrypted = Base64.getDecoder().decode(encrypted_str);
//            System.out.println("D: " + System.currentTimeMillis());
//            String str = new String(AES.decrypt(decrypted, key, iv), StandardCharsets.UTF_8);
//            System.out.println("E: " + System.currentTimeMillis());
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

}
