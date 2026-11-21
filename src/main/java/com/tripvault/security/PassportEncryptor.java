package com.tripvault.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * JPA AttributeConverter that transparently encrypts passport numbers with AES-256-GCM.
 *
 * Stored format:  "v1:" + Base64( IV[12 bytes] || ciphertext || GCM tag[16 bytes] )
 *
 *  - AES-GCM gives confidentiality AND integrity: if anyone modifies the stored value in the
 *    database, decryption fails instead of returning tampered data.
 *  - A fresh random 12-byte IV per value means the same passport encrypts to a different value
 *    every time, so an attacker cannot spot duplicates or build a lookup table.
 *  - "v1:" is a key-version prefix. To rotate keys later, add "v2:" with a new key and decrypt
 *    old rows by their prefix, without breaking existing data.
 *  - The 32-byte key is injected by Spring from configuration (environment variable
 *    TRIPVAULT_KEY or a git-ignored file); it is never hard-coded and never stored in the
 *    database, so a database dump alone cannot be decrypted.
 *
 * Hibernate creates this converter through Spring (Spring Boot registers a SpringBeanContainer),
 * which is why constructor injection with @Value works here.
 */
@Converter
public class PassportEncryptor implements AttributeConverter<String, String> {

    private static final String VERSION_PREFIX = "v1:";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;      // NIST-recommended IV size for GCM
    private static final int TAG_LENGTH_BITS = 128;     // full-strength authentication tag
    private static final int KEY_LENGTH_BYTES = 32;     // 256-bit AES key

    private final SecretKey key;
    private final SecureRandom secureRandom = new SecureRandom();   // created once, reused

    public PassportEncryptor(@Value("${tripvault.encryption.key}") String base64Key) {
        this.key = parseKey(base64Key);
    }

    /** Fail fast at startup with a clear message if the key is missing or the wrong size. */
    static SecretKey parseKey(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException(
                    "Encryption key missing: set TRIPVAULT_KEY or run scripts/create-encryption-key.ps1");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Encryption key is not valid Base64");
        }
        if (raw.length != KEY_LENGTH_BYTES) {
            throw new IllegalStateException(
                    "Encryption key must be " + KEY_LENGTH_BYTES + " bytes (AES-256), got " + raw.length);
        }
        return new SecretKeySpec(raw, "AES");
    }

    /** Called by Hibernate before writing to the database. */
    @Override
    public String convertToDatabaseColumn(String plainText) {
        if (plainText == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] payload = ByteBuffer.allocate(iv.length + cipherText.length)
                    .put(iv).put(cipherText).array();
            return VERSION_PREFIX + Base64.getEncoder().encodeToString(payload);
        } catch (GeneralSecurityException e) {
            // Never include the plaintext in exception messages or logs.
            throw new IllegalStateException("Passport encryption failed", e);
        }
    }

    /** Called by Hibernate after reading from the database. */
    @Override
    public String convertToEntityAttribute(String stored) {
        if (stored == null) {
            return null;
        }
        if (!stored.startsWith(VERSION_PREFIX)) {
            throw new IllegalStateException("Unknown passport ciphertext version");
        }
        try {
            byte[] payload = Base64.getDecoder().decode(stored.substring(VERSION_PREFIX.length()));

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key,
                    new GCMParameterSpec(TAG_LENGTH_BITS, payload, 0, IV_LENGTH_BYTES));
            byte[] plain = cipher.doFinal(payload, IV_LENGTH_BYTES, payload.length - IV_LENGTH_BYTES);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // GCM tag mismatch => data was tampered with or the wrong key is configured.
            throw new IllegalStateException("Passport decryption failed (tampered data or wrong key)", e);
        }
    }
}
