package io.micronaut.security.token.jwt.signature.secret;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretSignatureBase64Test {

    // Behaviour only: the JDK rejects this secret too. Configuration secrets are not request data, so routing
    // them through Base64Utils is defence in depth; Base64DecoderUsageTest in the security module protects the wiring.
    @Test
    void base64SecretWithInvalidPaddingIsRejectedWithIllegalArgumentException() {
        SecretSignatureConfiguration config = new SecretSignatureConfiguration("generator");
        config.setSecret("A".repeat(64) + "=");
        config.setBase64(true);

        assertThrows(IllegalArgumentException.class, () -> new SecretSignature(config));
    }
}
