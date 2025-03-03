package com.temp;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AES256GCMExample1 {
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        String plaintext = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjY0ZDM4MzZmMjk2ZmYzYzMzNjg1MTFhOTEwYzNiNmRiMWI0NzQ5NWEiLCJzZXNzaW9uSWQiOiI1YzlhYzY3Yy1kMTJiLTRjODktYmU0ZC0yOGVkNzAwN2Q5MjUiLCJtZXJjaGFudElkIjoiNjdhOWIzOWEwNDc2YmY0OGNmZGQxYjEwIiwiaWF0IjoxNzM5NzEwMzg0LCJleHAiOjE3Mzk3MzkxODR9.RTjPHhQ6kzdiLxmFbFSxlmIsxeAFPvsjlDpsQ8MkJVSSxsgJkN7hbKVeTZDH8m89-vXaxkMcVz5pc2JWGEvtqWvSRgTEFh-FKmeQvWPOUxcIg8esLqrix8wAkgYX8PB9b7reNnT-HXyxhAsgxRlypuZ8wsi5d36MXV_5u8WzV0TLW2fHDX03vanI0WKNcRY-ZLAkgQoYjjl80FtbZMF-Dx_XgTpIOONVg_ovk_n4z6f__t4op549DhNT31cwAU2kt2ZJWu0CUdxWgjd4WNCCqMXJgxFkjhCY3JEWeXcEE1cSs79aj1tPhBNCV2w0Z3dWXoTK9TJ_hIzjbFPZ-wf1pg";
        
        // Generate random AES key
        SecretKey key = generateKey();
        
        // Encrypt
        byte[] iv = generateIV();
        String encryptedText = encrypt(plaintext, key, iv);
        System.out.println("Encrypted: " + encryptedText);
        
        // Decrypt
        String decryptedText = decrypt(encryptedText, key, iv);
        System.out.println("Decrypted: " + decryptedText);
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    public static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encryptedText, SecretKey key, byte[] iv) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] encryptedBytes = new byte[decodedBytes.length - GCM_IV_LENGTH];
        System.arraycopy(decodedBytes, GCM_IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
