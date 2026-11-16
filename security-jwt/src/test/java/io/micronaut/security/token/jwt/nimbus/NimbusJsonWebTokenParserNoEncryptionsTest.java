package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.AuthenticationMapper;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.ENCRYPTION_SECRET;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.plainJwe;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = JweTestFixtures.SIGNATURE_SECRET)
@Property(name = "spec.name", value = "NimbusJsonWebTokenParserNoEncryptionsTest")
@MicronautTest(startApplication = false)
class NimbusJsonWebTokenParserNoEncryptionsTest {
    @Test
    void jweIsNotParsedAndDoesNotThrowWithoutEncryptionConfigurations(JsonWebTokenParser<JWT> parser,
                                                                      AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = plainJwe(ENCRYPTION_SECRET);

        assertTrue(assertDoesNotThrow(() -> parser.parse(token)).isEmpty());
        assertTrue(assertDoesNotThrow(() -> parser.parseClaims(token)).isEmpty());
        assertNull(assertDoesNotThrow(() -> authenticationMapper.of(token)));
    }
}
