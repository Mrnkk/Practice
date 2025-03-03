package com.temp;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AES256GCMExample2 {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // 128-bit tag
    private static final int IV_LENGTH = 12; // 12 bytes IV recommended for GCM

    // Convert the provided hex key into a SecretKey
    private static SecretKey getSecretKeyFromHex(String hexKey) {
        byte[] keyBytes = hexStringToByteArray(hexKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv); // Generate a random IV

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Concatenate IV + CipherText and encode in Base64
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encryptedBase64, SecretKey key) throws Exception {
        byte[] encryptedCombined = Base64.getDecoder().decode(encryptedBase64);

        byte[] iv = new byte[IV_LENGTH];
        byte[] encryptedBytes = new byte[encryptedCombined.length - IV_LENGTH];

        System.arraycopy(encryptedCombined, 0, iv, 0, IV_LENGTH);
        System.arraycopy(encryptedCombined, IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // Helper method to convert a hex string into a byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        try {
            String hexKey = "ad81ee573017335a8df88716fdecce3e30ebe54bd0663dbe290e750cf82cc06b";
            SecretKey key = getSecretKeyFromHex(hexKey);

            String plaintext = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBJZCI6IjY0ZDM4MzZmMjk2ZmYzYzMzNjg1MTFhOTEwYzNiNmRiMWI0NzQ5NWEiLCJzZXNzaW9uSWQiOiI1YzlhYzY3Yy1kMTJiLTRjODktYmU0ZC0yOGVkNzAwN2Q5MjUiLCJtZXJjaGFudElkIjoiNjdhOWIzOWEwNDc2YmY0OGNmZGQxYjEwIiwiaWF0IjoxNzM5NzEwMzg0LCJleHAiOjE3Mzk3MzkxODR9.RTjPHhQ6kzdiLxmFbFSxlmIsxeAFPvsjlDpsQ8MkJVSSxsgJkN7hbKVeTZDH8m89-vXaxkMcVz5pc2JWGEvtqWvSRgTEFh-FKmeQvWPOUxcIg8esLqrix8wAkgYX8PB9b7reNnT-HXyxhAsgxRlypuZ8wsi5d36MXV_5u8WzV0TLW2fHDX03vanI0WKNcRY-ZLAkgQoYjjl80FtbZMF-Dx_XgTpIOONVg_ovk_n4z6f__t4op549DhNT31cwAU2kt2ZJWu0CUdxWgjd4WNCCqMXJgxFkjhCY3JEWeXcEE1cSs79aj1tPhBNCV2w0Z3dWXoTK9TJ_hIzjbFPZ-wf1pg";
            System.out.println("Original Text: " + plaintext);

            String encryptedText = "/inuL8gn1+YYx6o1wapFBgfck/gr4oS/JudUNU6BUrKW6c9jC78D1fhqrwIBkegkgN11t5WsEfF9TQpOTHi8af+dXz3WjhfW/N2DAmV3y0CqhdPn4d1tWj2zbS6n6ombWa9j255Se5Q/oTryQJ0jEnSCh2qF7yOy7Gnik1EWjJnwwosR6bZosLeJXllU1sLPHfjZvWXZr2Sd+Cz4LAlw4dWBRn1ZY4scnU709jnjHsW1tkoDUNVvSqf1TrWqQPA/Tyax0lz8yl+T9jbNP3pk4diubwSIElziIdyhWQX3B+JROv8MM3dgu84gjBsawIKoDaLfx02B8dESfReDpGBteeFEyussOry4fsl5Y0/wPqba3DqWCQDm/4HRXGo+lHSSVhsUiwxMFaP0vqkovdws/+akTJUlLspqyh3JvmTd/283AjzwRWGslaiN/48RSzjz6Ek9bGREAbdsU52azCvmRkspXF9tSZKwqfeUjHIlvHATNwberc8mNt87IHwTGYzjoA2HguAHKvhKvl/0mHYIprPR2JjnoCqTp6+OkEWvekX8E0kXQFEgY2oQ6R+hKA1PyETqwJUKEBk1Hr1tJPO5f0bl7pAGtJYRkh/rNfVzDqnfTDIDmzygVe6YjH3g02ychmDCGJqqblV7WQg0VnVTtMrMYW6m5nr47KTXZmklmRCh1KaMr7RgClln4d1lPLGD2OChVtsZtcNOd0Z0ZfnCn73725q/DNsMmvTELgN6Z8W9MIMAQBoCzcBphONn8BMAqDI/fJ5ojC6h2obefvbGDbBxFdVtHCUFnJzfXc6RF0LBj4E6147JkcI9LDPFugGMgn2YCAq+ikwfBmiVWlzmlO13KkIr+zoorzremWpkPYrDBQL+o/cTuVeh9M/68FAf";
            System.out.println("Encrypted (Base64): " + encryptedText);

            String decryptedText = decrypt(encryptedText, key);
            System.out.println("Decrypted Text: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
