package de.pterocloud.encryptedconnection.crypto;

import java.security.MessageDigest;

public class SHA256 {

    public static byte[] hash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
