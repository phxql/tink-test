package de.mkammerer.tinktest;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.aead.ChaCha20Poly1305KeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class Main {
    private final static char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        // Initialize stuff
        TinkConfig.register();

        // Create a new key
        KeysetHandle key1 = generateKey(ChaCha20Poly1305KeyManager.chaCha20Poly1305Template());
        // Store it in a file
        storeKey(key1, "aead-key-1.json");

        // Load the key from the file again
        KeysetHandle key2 = loadKey("aead-key-1.json");

        // Rotate the key (both can be used for decryption, but only the primary one is used for encryption)
        // The new key can even be of another algorithm
        KeysetHandle key3 = rotateKey(key2, AesGcmKeyManager.aes128GcmTemplate());
        // And also store it
        storeKey(key3, "rotated-aead-key-3.json");

        // This is our plaintext
        byte[] plaintext = "hello, tink".getBytes(StandardCharsets.UTF_8);

        // Create a HMAC key
        KeysetHandle hmacKey = generateKey(HmacKeyManager.hmacSha256Template());
        // And store if
        storeKey(hmacKey, "hmac-key.json");
        // Calculate the MAC
        byte[] mac = calculateMac(plaintext, hmacKey);
        // And print it
        System.out.println("Mac: " + bytesToHex(mac));

        // Generate a Public-Private keypair
        KeysetHandle signatureKey = generateKey(Ed25519PrivateKeyManager.ed25519Template());
        // Store it
        storeKey(signatureKey, "signature-key.json");
        // Create a signature
        byte[] signature = sign(plaintext, signatureKey);
        // And verify it
        verify(signature, plaintext, signatureKey.getPublicKeysetHandle());

        // Encrypt plaintext with key-1
        byte[] ciphertext = encryptAead(key1, plaintext);
        System.out.println("Ciphertext: " + bytesToHex(ciphertext));

        // And decrypt it with key-3 (which contains key-2, which is the same as key-1)
        byte[] plaintext2 = decryptAead(key3, ciphertext);
        System.out.println("Plaintext: " + new String(plaintext2, StandardCharsets.UTF_8));

        // Now try to encrypt with key-3 and decrypt with key-1. This must fail.
        try {
            byte[] ciphertext2 = encryptAead(key3, plaintext);
            decryptAead(key1, ciphertext2);
            throw new AssertionError("Expected failure");
        } catch (GeneralSecurityException e) {
            // Expected...
        }
    }

    private static KeysetHandle rotateKey(KeysetHandle oldKey, KeyTemplate newKeyType) throws GeneralSecurityException {
        KeysetManager keysetManager = KeysetManager.withKeysetHandle(oldKey);
        return keysetManager.add(newKeyType).getKeysetHandle();
    }

    private static void verify(byte[] signature, byte[] plaintext, KeysetHandle publicSignatureKey) throws GeneralSecurityException {
        PublicKeyVerify publicKeyVerify = publicSignatureKey.getPrimitive(PublicKeyVerify.class);
        publicKeyVerify.verify(signature, plaintext);
        System.out.println("Signature verified");
    }

    private static byte[] sign(byte[] plaintext, KeysetHandle signatureKey) throws GeneralSecurityException {
        PublicKeySign publicKeySign = signatureKey.getPrimitive(PublicKeySign.class);
        byte[] signature = publicKeySign.sign(plaintext);
        System.out.println("Signature: " + bytesToHex(signature));
        return signature;
    }

    private static byte[] calculateMac(byte[] plaintext, KeysetHandle macKey) throws GeneralSecurityException {
        Mac hmac = macKey.getPrimitive(Mac.class);
        return hmac.computeMac(plaintext);
    }

    private static byte[] decryptAead(KeysetHandle key, byte[] ciphertext) throws GeneralSecurityException {
        Aead aead = key.getPrimitive(Aead.class);
        return aead.decrypt(ciphertext, new byte[0]);
    }

    private static byte[] encryptAead(KeysetHandle key, byte[] plaintext) throws GeneralSecurityException {
        Aead aead = key.getPrimitive(Aead.class);
        return aead.encrypt(plaintext, new byte[0]);
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static KeysetHandle loadKey(String fileName) throws GeneralSecurityException, IOException {
        return CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(fileName)));
    }

    private static void storeKey(KeysetHandle keysetHandle, String fileName) throws IOException {
        CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(fileName)));
    }

    private static KeysetHandle generateKey(KeyTemplate template) throws GeneralSecurityException {
        return KeysetHandle.generateNew(template);
    }
}
