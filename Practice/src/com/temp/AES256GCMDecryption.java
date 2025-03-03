package com.temp;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES256GCMDecryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // in bits

    

    public static void main(String[] args) {
        try {
            String key = "ad81ee573017335a8df88716fdecce3e30ebe54bd0663dbe290e750cf82cc06b";
            String plainText = "Kjj68LTWRlO9vOsEG0jkaaXRp52s13vFjiXFJ6Rxhp8Aq+7XZWg4etg2A9C+iuaOiZugx8tZ/Mz32BeNuVfNZBDHhlNEW4kFg4Vc5w/DOPdsDHRG12VAc6CZEsdCzgUgmal/MPnk3NVPgWff71J2IseeQ/Qft+dWI96FrHN8lbtTUZ6yKn7zkNBqtPtqnjv3Dfh0R8k/Zw4TTIGSSwKtm3SWlUhtmcNIaXipbA+o1Zq8LCZS7EN869wkSBIaZpHa6PNOdrfvMML1oH2UZn0phrfKodkWbdo64GtA7SXrPX4TP9eSFmgJgbX3YCQYakRMVglG0/cV5mA+0ScXHKOIq/cPxPzms7dynxz31Tjv9I/ziON4s1TcZY2cbH5/bUcxNygOa99uFBCCwHkgXOz65YmmLLQKeQaGadCfsTId3JXvZDE7dND65kmOHHGJTDbj5DBg0IMlDntpW6EEyQp2gDDmJvFe+ssATqKnqdrsuk/W3a2/vWoI67HaI3uCqgfEV2fsXxBuKilzMqsIcSJrtzu1BczQjYkJiMaA5MrLv0cwOa5eJzQmGSc2PGyxDE8wM7I8+iBkHiBlyjsOzXI8gP+NHCftpl8WT2eyBIyB418IfOVO28wiElytIjcR59x/K5oioHbqvOF3coahWAvY9OB6BYrqL4soEBYpk69pMe9BN2OJapmH6r1vamz3+kp2RRTaDdstvChQl8bOlSnAUlRz6G8BMKb3g/WS5gYplrgOwroigzbZIagAmZNq9sD0WQrMaxd0oMbZWtEfThOVKVEXp8tjECLHlf+4qSx4QkWYWmUTD68+k0m8QGnnpvUIH99Vs5KglluUGmjOjbl7zDGwnNUMCI6DoFNCGpDrXAB2SnEZQE/y/bcCMkgVbLto";
            //String plainText = "ZzdyZnhiM2RGbmw5K25ScE5sZm5rV1pxUHpwMktlYnRJQ2JMTXRIbHUzb0pKMG5kYmx5aEIxZTdzaERFZWVkUjJsdEtibUoxZ2R5VUhpV054c3EwZE9HYi93WXVPTE1yY09DNE93dGVzaEh2UU9OQ2tOd3cwK0VhbzQ1SFpxdHUyVFpEb2NWUWlxUCtXY0lxbzIxcDZMMW9IK29PVWh0SE5oTm9iWi9jekc5b1JpVlA0VzIvLzZMK1d0cWNwL01INTlxOA%3D%3D";
            //String encryptedText = encrypt(plainText, key);
            //System.out.println("Encrypted Text : " + encryptedText);
            String decryptedData = decrypt(plainText, key);
            System.out.println("Decrypted Text: " + decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static String encrypt(String plaintext, String passphrase) throws Exception {
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(nonce);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 40000, 256);
        SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedData = new byte[salt.length + nonce.length + ciphertext.length];
        
        System.arraycopy(salt, 0, encryptedData, 0, salt.length);
        System.arraycopy(nonce, 0, encryptedData, salt.length, nonce.length);
        System.arraycopy(ciphertext, 0, encryptedData, salt.length + nonce.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public static String decryptOld(String ciphertext, String passphrase) throws Exception {
        byte[] input = Base64.getDecoder().decode(ciphertext);
        
        byte[] salt = Arrays.copyOfRange(input, 0, 16);
        byte[] nonce = Arrays.copyOfRange(input, 16, 28);
        byte[] encryptedData = Arrays.copyOfRange(input, 28, input.length - 16);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 40000, 256);
        SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
    
    public static String decrypt(String ciphertext, String passphrase) throws Exception {
        try {
            byte[] input = Base64.getDecoder().decode(ciphertext);
            if (input.length < 28) { // Minimum length check (16 bytes salt + 12 bytes nonce)
                throw new IllegalArgumentException("Invalid encrypted data length");
            }
 
            byte[] salt = Arrays.copyOfRange(input, 0, 16);
            byte[] nonce = Arrays.copyOfRange(input, 16, 28);
            byte[] encryptedData = Arrays.copyOfRange(input, 28, input.length);
 
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 40000, 256);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
 
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
 
            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new SecurityException("Decryption failed: Invalid passphrase or corrupted data", e);
        } catch (IllegalArgumentException e) {
            throw new SecurityException("Decryption failed: Invalid input format", e);
        }
    }
}
