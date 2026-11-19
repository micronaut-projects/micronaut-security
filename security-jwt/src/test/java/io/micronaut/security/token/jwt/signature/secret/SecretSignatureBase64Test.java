package io.micronaut.security.token.jwt.signature.secret;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretSignatureBase64Test {

    // Configuration secrets are not request data: routing them through Base64Utils is defence in depth.
    @Test
    void base64SecretWithPaddingThatDoesNotCompleteTheFinalUnitIsRejected() {
        SecretSignatureConfiguration config = new SecretSignatureConfiguration("generator");
        config.setSecret("A".repeat(64) + "=");
        config.setBase64(true);

        assertThrows(IllegalArgumentException.class, () -> new SecretSignature(config));
    }
}
