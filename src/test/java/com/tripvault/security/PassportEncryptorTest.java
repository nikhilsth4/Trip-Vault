package com.tripvault.security;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Unit tests for the AES-256-GCM passport converter (no Spring context needed). */
class PassportEncryptorTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]); // test-only key
    private final PassportEncryptor encryptor = new PassportEncryptor(KEY);

    @Test
    void encryptThenDecryptReturnsOriginal() {
        String stored = encryptor.convertToDatabaseColumn("N1234567");
        assertThat(encryptor.convertToEntityAttribute(stored)).isEqualTo("N1234567");
    }

    @Test
    void ciphertextIsVersionedAndDoesNotContainPlaintext() {
        String stored = encryptor.convertToDatabaseColumn("N1234567");
        assertThat(stored).startsWith("v1:").doesNotContain("N1234567");
    }

    @Test
    void samePassportEncryptsDifferentlyEachTime() {   // random IV per value
        assertThat(encryptor.convertToDatabaseColumn("N1234567"))
                .isNotEqualTo(encryptor.convertToDatabaseColumn("N1234567"));
    }

    @Test
    void tamperedCiphertextIsRejected() {               // GCM integrity check
        String stored = encryptor.convertToDatabaseColumn("N1234567");
        byte[] payload = Base64.getDecoder().decode(stored.substring(3));
        payload[payload.length - 1] ^= 1;                // flip one bit
        String tampered = "v1:" + Base64.getEncoder().encodeToString(payload);

        assertThatThrownBy(() -> encryptor.convertToEntityAttribute(tampered))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void wrongKeyCannotDecrypt() {
        String stored = encryptor.convertToDatabaseColumn("N1234567");
        byte[] otherKey = new byte[32];
        otherKey[0] = 1;
        PassportEncryptor other = new PassportEncryptor(Base64.getEncoder().encodeToString(otherKey));

        assertThatThrownBy(() -> other.convertToEntityAttribute(stored))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void keyMustBe32Bytes() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        assertThatThrownBy(() -> new PassportEncryptor(shortKey))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("32 bytes");
        assertThatThrownBy(() -> new PassportEncryptor(""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("missing");
    }
}
