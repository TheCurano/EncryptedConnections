import de.pterocloud.encryptedconnection.crypto.AES;
import de.pterocloud.encryptedconnection.crypto.ChaCha20;

import javax.crypto.SecretKey;

public class EncryptionTest {

    public static void main(String[] args) {
        System.out.println("Testing encryption performance...");
        System.out.println("Million iterations per encryption algorithm (in mills)");
        SecretKey aesKey = AES.generateKey();
        byte[] iv = AES.generateIV();
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000000; i++) {
            try {
                byte[] encrypted = AES.encrypt("Hello World".getBytes(), aesKey, iv);
                byte[] decrypted = AES.decrypt(encrypted, aesKey, iv);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("AES: " + (System.currentTimeMillis() - start));

        SecretKey chachaKey = ChaCha20.generateKey();
        byte[] nonce = ChaCha20.generateNonce();
        start = System.currentTimeMillis();
        for (int i = 0; i < 1000000; i++) {
            try {
                byte[] encrypted = ChaCha20.encrypt("Hello World".getBytes(), chachaKey, nonce, i);
                byte[] decrypted = ChaCha20.decrypt(encrypted, chachaKey, nonce, i);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("ChaCha20: " + (System.currentTimeMillis() - start));
    }

}
