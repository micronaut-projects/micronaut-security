package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationMapper;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.ENCRYPTION_SECRET;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.OTHER_ENCRYPTION_SECRET;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.SUBJECT;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.nestedJwe;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.plainJwe;
import static io.micronaut.security.token.jwt.nimbus.JweTestFixtures.signedJwt;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = JweTestFixtures.SIGNATURE_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.generator.secret", value = JweTestFixtures.ENCRYPTION_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.generator.base64", value = "false")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.generator.jwe-algorithm", value = "dir")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.generator.encryption-method", value = "A256GCM")
@Property(name = "spec.name", value = "NimbusJsonWebTokenParserUndecryptableJweTest")
@MicronautTest(startApplication = false)
class NimbusJsonWebTokenParserUndecryptableJweTest {
    @Test
    void jweEncryptedWithDifferentKeyIsNotParsedAndDoesNotThrow(JsonWebTokenParser<JWT> parser,
                                                                AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = nestedJwe(OTHER_ENCRYPTION_SECRET);
        assertEquals(4, token.chars().filter(c -> c == '.').count());

        Optional<JWT> jwt = assertDoesNotThrow(() -> parser.parse(token));
        assertTrue(jwt.isEmpty());

        Optional<Claims> claims = assertDoesNotThrow(() -> parser.parseClaims(token));
        assertTrue(claims.isEmpty());

        Authentication authentication = assertDoesNotThrow(() -> authenticationMapper.of(token));
        assertNull(authentication);
    }

    @Test
    void plainJweEncryptedWithDifferentKeyIsNotParsedAndDoesNotThrow(JsonWebTokenParser<JWT> parser,
                                                                     AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = plainJwe(OTHER_ENCRYPTION_SECRET);

        assertTrue(assertDoesNotThrow(() -> parser.parse(token)).isEmpty());
        assertTrue(assertDoesNotThrow(() -> parser.parseClaims(token)).isEmpty());
        assertNull(assertDoesNotThrow(() -> authenticationMapper.of(token)));
    }

    @Test
    void plainJweEncryptedWithConfiguredKeyIsParsedAsDecryptedJwe(JsonWebTokenParser<JWT> parser,
                                                                  AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = plainJwe(ENCRYPTION_SECRET);

        Optional<JWT> jwt = parser.parse(token);
        assertTrue(jwt.isPresent());
        EncryptedJWT encryptedJWT = assertInstanceOf(EncryptedJWT.class, jwt.get());
        assertEquals(JWEObject.State.DECRYPTED, encryptedJWT.getState());

        Optional<Claims> claims = parser.parseClaims(token);
        assertTrue(claims.isPresent());
        assertEquals(SUBJECT, claims.get().get("sub"));

        Authentication authentication = authenticationMapper.of(token);
        assertEquals(SUBJECT, authentication.getName());
    }

    @Test
    void jweEncryptedWithConfiguredKeyStillParses(JsonWebTokenParser<JWT> parser,
                                                  AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = nestedJwe(ENCRYPTION_SECRET);
        assertEquals(4, token.chars().filter(c -> c == '.').count());

        Optional<JWT> jwt = parser.parse(token);
        assertTrue(jwt.isPresent());
        assertInstanceOf(SignedJWT.class, jwt.get());

        Optional<Claims> claims = parser.parseClaims(token);
        assertTrue(claims.isPresent());
        assertEquals(SUBJECT, claims.get().get("sub"));

        Authentication authentication = authenticationMapper.of(token);
        assertEquals(SUBJECT, authentication.getName());
    }

    @Test
    void jweGeneratedByTokenGeneratorStillParses(TokenGenerator tokenGenerator,
                                                 JsonWebTokenParser<JWT> parser,
                                                 AuthenticationMapper authenticationMapper) {
        String token = tokenGenerator.generateToken(Map.of("sub", "248289761001", "name", "Jane Doe")).orElseThrow();
        assertEquals(4, token.chars().filter(c -> c == '.').count());

        Optional<JWT> jwt = parser.parse(token);
        assertTrue(jwt.isPresent());
        assertInstanceOf(SignedJWT.class, jwt.get());

        Authentication authentication = authenticationMapper.of(token);
        assertEquals("248289761001", authentication.getName());
        assertEquals("Jane Doe", authentication.getAttributes().get("name"));
    }

    @Test
    void signedJwtStillParses(JsonWebTokenParser<JWT> parser,
                              AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = signedJwt().serialize();
        assertEquals(2, token.chars().filter(c -> c == '.').count());

        Optional<JWT> jwt = parser.parse(token);
        assertTrue(jwt.isPresent());
        assertInstanceOf(SignedJWT.class, jwt.get());

        Optional<Claims> claims = parser.parseClaims(token);
        assertFalse(claims.isEmpty());
        assertEquals(SUBJECT, claims.get().get("sub"));

        Authentication authentication = authenticationMapper.of(token);
        assertEquals(SUBJECT, authentication.getName());
    }
}
