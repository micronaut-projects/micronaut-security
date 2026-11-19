package io.micronaut.security.token.jwt.generator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SignedRefreshTokenGeneratorBase64Test {

    // Configuration secrets are not request data: routing them through Base64Utils is defence in depth.
    @Test
    void base64SecretWithPaddingThatDoesNotCompleteTheFinalUnitIsRejected() {
        RefreshTokenConfigurationProperties config = new RefreshTokenConfigurationProperties();
        config.setSecret("A".repeat(64) + "=");
        config.setBase64(true);

        assertThrows(IllegalArgumentException.class, () -> new SignedRefreshTokenGenerator(config));
    }
}
