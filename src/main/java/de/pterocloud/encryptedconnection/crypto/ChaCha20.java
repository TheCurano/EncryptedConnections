package de.pterocloud.encryptedconnection.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ChaCha20 {

    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] nonce, int counter) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
        cipher.init(Cipher.ENCRYPT_MODE, key, param);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] cipherText, SecretKey key, byte[] nonce, int counter) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
        cipher.init(Cipher.DECRYPT_MODE, key, param);
        return cipher.doFinal(cipherText);
    }

    public static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
            keyGen.init(256, SecureRandom.getInstanceStrong());
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] generateNonce() {
        byte[] newNonce = new byte[12];
        new SecureRandom().nextBytes(newNonce);
        return newNonce;
    }

    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }
}
