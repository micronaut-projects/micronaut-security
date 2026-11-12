package io.micronaut.security.docs.jwtencryption;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryption;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Named;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "RSAOAEPEncryptionTest")
@Property(name = "pem.path", value = "src/test/resources/rsa-2048bit-key-pair.pem")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest(startApplication = false)
class RSAOAEPEncryptionTest {

    @Test
    void tokensAreEncryptedWithTheRsaKeyPair(@Named("generator") EncryptionConfiguration encryptionConfiguration,
                                             TokenGenerator tokenGenerator,
                                             TokenValidator<?> tokenValidator) throws Exception {
        assertInstanceOf(RSAEncryption.class, encryptionConfiguration);
        Optional<String> token = tokenGenerator.generateToken(Authentication.build("sherlock"), 3600);
        assertTrue(token.isPresent());
        assertInstanceOf(EncryptedJWT.class, JWTParser.parse(token.get()));
        Authentication authentication = Mono.from(tokenValidator.validateToken(token.get(), null)).block();
        assertNotNull(authentication);
        assertEquals("sherlock", authentication.getName());
    }
}
