package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = NimbusJsonWebTokenParserMultipleEncryptionsTest.SIGNATURE_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.secret", value = NimbusJsonWebTokenParserMultipleEncryptionsTest.ENCRYPTION_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.base64", value = "false")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.jwe-algorithm", value = "dir")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.first.encryption-method", value = "A256GCM")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.secret", value = NimbusJsonWebTokenParserMultipleEncryptionsTest.ENCRYPTION_SECRET)
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.base64", value = "false")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.jwe-algorithm", value = "dir")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.encryptions.secret.second.encryption-method", value = "A256GCM")
@Property(name = "spec.name", value = "NimbusJsonWebTokenParserMultipleEncryptionsTest")
@MicronautTest(startApplication = false)
class NimbusJsonWebTokenParserMultipleEncryptionsTest {
    static final String SIGNATURE_SECRET = "pleaseChangeThisSecretForANewOne";
    static final String ENCRYPTION_SECRET = "anEncryptionSecretOf32Characters";

    @Test
    void jweDecryptedByFirstConfigurationIsNotDecryptedAgainByTheNextOne(JsonWebTokenParser<JWT> parser,
                                                                         AuthenticationMapper authenticationMapper) throws JOSEException {
        String token = plainJwe();

        Optional<JWT> jwt = assertDoesNotThrow(() -> parser.parse(token));
        assertTrue(jwt.isPresent());
        EncryptedJWT encryptedJWT = assertInstanceOf(EncryptedJWT.class, jwt.get());
        assertEquals(JWEObject.State.DECRYPTED, encryptedJWT.getState());

        assertTrue(assertDoesNotThrow(() -> parser.parseClaims(token)).isPresent());
        assertEquals("1234567890", assertDoesNotThrow(() -> authenticationMapper.of(token)).getName());
    }

    private static String plainJwe() throws JOSEException {
        EncryptedJWT encryptedJWT = new EncryptedJWT(
            new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM),
            new JWTClaimsSet.Builder().subject("1234567890").build());
        encryptedJWT.encrypt(new DirectEncrypter(ENCRYPTION_SECRET.getBytes(StandardCharsets.UTF_8)));
        return encryptedJWT.serialize();
    }
}
