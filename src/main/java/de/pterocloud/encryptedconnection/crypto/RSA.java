package de.pterocloud.encryptedconnection.crypto;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;

/**
 * The RSA Utility to encrypt the first handshake.
 * Encryption Mode: RSA
 */
public class RSA {

    public static byte[] decrypt(PrivateKey privateKey, byte[] message) {
        try {
            // Open with private key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(message);

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(message);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static PublicKey importPublicKey(String pubFile) {
        ObjectInputStream keyIn = null;
        PublicKey publicKey = null;
        try {
            keyIn = new ObjectInputStream(new FileInputStream(pubFile));
            publicKey = (PublicKey) keyIn.readObject();
            keyIn.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey importPrivateKey(String privFile) {

        ObjectInputStream keyIn = null;
        PrivateKey privateKey = null;
        try {
            keyIn = new ObjectInputStream(new FileInputStream(privFile));
            privateKey = (PrivateKey) keyIn.readObject();
            keyIn.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static void generateRSAKeyToFile(String privateKeyFileName, String publicKeyFileName, Integer KEYSIZE) {
        try {
            KeyPairGenerator pairgen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            pairgen.initialize(KEYSIZE, random);
            KeyPair keyPair = pairgen.generateKeyPair();
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(publicKeyFileName));
            out.writeObject(keyPair.getPublic());
            out.close();
            out = new ObjectOutputStream(new FileOutputStream(privateKeyFileName));
            out.writeObject(keyPair.getPrivate());
            out.close();
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generateRSAKey(Integer KEYSIZE) {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator pairgen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            pairgen.initialize(KEYSIZE, random);
            keyPair = pairgen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return keyPair;
    }


}
