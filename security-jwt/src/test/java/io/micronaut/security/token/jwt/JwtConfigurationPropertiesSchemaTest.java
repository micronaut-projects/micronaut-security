package io.micronaut.security.token.jwt;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertDefaults;

class JwtConfigurationPropertiesSchemaTest {
    @Test
    void generatedConfigurationSchemasContainDefaults() throws IOException {
        assertDefaults("io.micronaut.security.token.jwt.config.JwtConfigurationProperties", Map.of(
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.token.jwt.endpoints.KeysControllerConfigurationProperties", Map.of(
            "enabled", true,
            "path", "/keys"
        ));
        assertDefaults("io.micronaut.security.token.jwt.generator.RefreshTokenConfigurationProperties", Map.of(
            "enabled", true,
            "jws-algorithm", "HS256",
            "base64", false
        ));
        assertDefaults("io.micronaut.security.token.jwt.nimbus.NimbusJsonWebTokenValidatorConfigurationProperties", Map.of(
            "reactive-validator", true,
            "validator", true,
            "reactive-validator-execute-on-blocking", false
        ));
        assertDefaults("io.micronaut.security.token.jwt.validator.JwtClaimsValidatorConfigurationProperties", Map.of(
            "subject-not-null", true,
            "not-before", false,
            "expiration", true,
            "nonce", true,
            "openid-idtoken", true
        ));
        assertDefaults("io.micronaut.security.token.jwt.signature.secret.SecretSignatureConfiguration", Map.of(
            "jws-algorithm", "HS256",
            "base64", false
        ));
        assertDefaults("io.micronaut.security.token.jwt.encryption.secret.SecretEncryptionConfiguration", Map.of(
            "base64", false
        ));
        assertDefaults("io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties", Map.of(
            "cache-expiration", 60,
            "key-type", "RSA"
        ));
    }
}
