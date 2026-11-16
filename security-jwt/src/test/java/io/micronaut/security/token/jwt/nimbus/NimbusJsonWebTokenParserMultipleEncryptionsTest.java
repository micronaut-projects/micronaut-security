package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.AuthenticationMapper;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.ENCRYPTION_SECRET;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.SUBJECT;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.plainJwe;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = JweTestFixtures.SIGNATURE_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.secret", value = JweTestFixtures.ENCRYPTION_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.base64", value = "false")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.jwe-algorithm", value = "dir")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.encryption-method", value = "A256GCM")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.secret", value = JweTestFixtures.ENCRYPTION_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.base64", value = "false")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.jwe-algorithm", value = "dir")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.encryption-method", value = "A256GCM")
@Property(name = "spec.name", value = "NimbusJsonWebTokenParserMultipleEncryptionsTest")
@MicronautTest(startApplication = false)
class NimbusJsonWebTokenParserMultipleEncryptionsTest {
    @Test
    void jweDecryptedByFirstConfigurationIsNotDecryptedAgainByTheNextOne(JsonWebTokenParser<JWT> parser,
                                                                         AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = plainJwe(ENCRYPTION_SECRET);

        Optional<JWT> jwt = assertDoesNotThrow(() -> parser.parse(token));
        assertTrue(jwt.isPresent());
        EncryptedJWT encryptedJWT = assertInstanceOf(EncryptedJWT.class, jwt.get());
        assertEquals(JWEObject.State.DECRYPTED, encryptedJWT.getState());

        assertTrue(assertDoesNotThrow(() -> parser.parseClaims(token)).isPresent());
        assertEquals(SUBJECT, assertDoesNotThrow(() -> authenticationMapper.of(token)).getName());
    }
}
