package io.micronaut.security.token.jwt.generator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SignedRefreshTokenGeneratorBase64Test {

    @Test
    void base64SecretWithPaddingThatDoesNotCompleteTheFinalUnitIsRejected() {
        RefreshTokenConfigurationProperties config = new RefreshTokenConfigurationProperties();
        config.setSecret("A".repeat(64) + "=");
        config.setBase64(true);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new SignedRefreshTokenGenerator(config));
        assertEquals("Invalid Base64 padding", e.getMessage());
    }
}
