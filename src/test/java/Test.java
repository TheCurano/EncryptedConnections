import de.pterocloud.encryptedconnection.*;
import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.RSA;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

public class Test {

    public static void main(String[] args) {
        /*
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
                    System.out.println("Time: " + System.currentTimeMillis());
                }));
            }
            Packet packet = new Packet("TEST");
            System.out.println("Started time: " + System.currentTimeMillis());
            client01.getEncryptedConnection().send(packet);
            if (client01.getEncryptedConnection().isConnected()) {
                System.out.println("Nice shit");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }*/
        try {
            System.out.println("Before: " + System.currentTimeMillis());
            SecretKey key = AES.generateKey();
            byte[] iv = AES.generateIV();
            System.out.println("A: " + System.currentTimeMillis());
            byte[] encrypted =  AES.encrypt("test".getBytes(StandardCharsets.UTF_8), key, iv);
            System.out.println("B: " + System.currentTimeMillis());
            String encrypted_str = Base64.getEncoder().encodeToString(encrypted);
            System.out.println("C: " + System.currentTimeMillis());
            byte[] decrypted = Base64.getDecoder().decode(encrypted_str);
            System.out.println("D: " + System.currentTimeMillis());
            String str = new String(AES.decrypt(decrypted, key, iv), StandardCharsets.UTF_8);
            System.out.println("E: " + System.currentTimeMillis());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
