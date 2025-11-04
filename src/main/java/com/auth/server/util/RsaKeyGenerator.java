package com.auth.server.util;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Utility class to generate and manage RSA key pairs for JWT signing.
 * Keys are stored in PKCS#8 format (private) and X.509 format (public).
 */
public class RsaKeyGenerator {

    private static final String PRIVATE_KEY_PATH = "src/main/resources/keys/private.key";
    private static final String PUBLIC_KEY_PATH = "src/main/resources/keys/public.key";
    private static final int KEY_SIZE = 2048;

    /**
     * Generate RSA key pair if keys don't exist
     */
    public static void generateKeysIfNotExists() {
        try {
            File privateKeyFile = new File(PRIVATE_KEY_PATH);
            File publicKeyFile = new File(PUBLIC_KEY_PATH);

            // Create keys directory if it doesn't exist
            File keysDir = new File("src/main/resources/keys");
            if (!keysDir.exists()) {
                keysDir.mkdirs();
            }

            // Generate keys if they don't exist
            if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
                System.out.println("Generating RSA key pair...");
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(KEY_SIZE);
                KeyPair keyPair = generator.generateKeyPair();

                savePrivateKey(keyPair.getPrivate(), PRIVATE_KEY_PATH);
                savePublicKey(keyPair.getPublic(), PUBLIC_KEY_PATH);

                System.out.println("RSA keys generated successfully!");
                System.out.println("Private key: " + PRIVATE_KEY_PATH);
                System.out.println("Public key: " + PUBLIC_KEY_PATH);
            } else {
                System.out.println("RSA keys already exist");
            }
        } catch (Exception e) {
            System.err.println("Error generating RSA keys: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Save private key in PKCS#8 format
     */
    private static void savePrivateKey(PrivateKey key, String filepath) throws Exception {
        byte[] pkcs8EncodedKey = key.getEncoded();
        String base64EncodedKey = Base64.getEncoder().encodeToString(pkcs8EncodedKey);

        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < base64EncodedKey.length(); i += 64) {
            sb.append(base64EncodedKey, i, Math.min(i + 64, base64EncodedKey.length()));
            sb.append("\n");
        }
        sb.append("-----END PRIVATE KEY-----");

        try (FileWriter writer = new FileWriter(filepath)) {
            writer.write(sb.toString());
        }
    }

    /**
     * Save public key in X.509 format
     */
    private static void savePublicKey(PublicKey key, String filepath) throws Exception {
        byte[] x509EncodedKey = key.getEncoded();
        String base64EncodedKey = Base64.getEncoder().encodeToString(x509EncodedKey);

        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64EncodedKey.length(); i += 64) {
            sb.append(base64EncodedKey, i, Math.min(i + 64, base64EncodedKey.length()));
            sb.append("\n");
        }
        sb.append("-----END PUBLIC KEY-----");

        try (FileWriter writer = new FileWriter(filepath)) {
            writer.write(sb.toString());
        }
    }

    /**
     * Load private key from file
     */
    public static PrivateKey loadPrivateKey(String filepath) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filepath)))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decodedKey = Base64.getDecoder().decode(key);
        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(decodedKey);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        return java.security.KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * Load public key from file
     */
    public static PublicKey loadPublicKey(String filepath) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filepath)))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decodedKey = Base64.getDecoder().decode(key);
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(decodedKey);
        return java.security.KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static void main(String[] args) {
        generateKeysIfNotExists();
    }
}
