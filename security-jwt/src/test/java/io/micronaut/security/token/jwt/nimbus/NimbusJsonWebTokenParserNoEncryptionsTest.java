package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.AuthenticationMapper;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = NimbusJsonWebTokenParserNoEncryptionsTest.SIGNATURE_SECRET)
@Property(name = "spec.name", value = "NimbusJsonWebTokenParserNoEncryptionsTest")
@MicronautTest(startApplication = false)
class NimbusJsonWebTokenParserNoEncryptionsTest {
    static final String SIGNATURE_SECRET = "pleaseChangeThisSecretForANewOne";
    private static final String ENCRYPTION_SECRET = "anEncryptionSecretOf32Characters";

    @Test
    void jweIsNotParsedAndDoesNotThrowWithoutEncryptionConfigurations(JsonWebTokenParser<JWT> parser,
                                                                      AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = plainJwe();

        assertTrue(assertDoesNotThrow(() -> parser.parse(token)).isEmpty());
        assertTrue(assertDoesNotThrow(() -> parser.parseClaims(token)).isEmpty());
        assertNull(assertDoesNotThrow(() -> authenticationMapper.of(token)));
    }

    private static String plainJwe() throws JOSEException {
        EncryptedJWT encryptedJWT = new EncryptedJWT(
            new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM),
            new JWTClaimsSet.Builder().subject("1234567890").build());
        encryptedJWT.encrypt(new DirectEncrypter(ENCRYPTION_SECRET.getBytes(StandardCharsets.UTF_8)));
        return encryptedJWT.serialize();
    }
}
