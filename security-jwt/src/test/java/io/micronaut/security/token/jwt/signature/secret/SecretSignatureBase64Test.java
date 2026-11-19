package io.micronaut.security.token.jwt.signature.secret;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretSignatureBase64Test {

    @Test
    void base64SecretWithPaddingThatDoesNotCompleteTheFinalUnitIsRejected() {
        SecretSignatureConfiguration config = new SecretSignatureConfiguration("generator");
        config.setSecret("A".repeat(64) + "=");
        config.setBase64(true);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new SecretSignature(config));
        assertEquals("Invalid Base64 padding", e.getMessage());
    }
}
