package io.micronaut.security.docs.jwtgeneratorrsa;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGenerator;
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "RSASignatureGeneratorTest")
@MicronautTest(startApplication = false)
class RSASignatureGeneratorTest {

    @Test
    void tokensAreSignedWithTheRsaSignatureGenerator(@Named("generator") SignatureGeneratorConfiguration signatureGeneratorConfiguration,
                                                    TokenGenerator tokenGenerator) throws Exception {
        assertInstanceOf(RSASignatureGenerator.class, signatureGeneratorConfiguration);
        Optional<String> token = tokenGenerator.generateToken(Authentication.build("sherlock"), 3600);
        assertTrue(token.isPresent());
        SignedJWT jwt = SignedJWT.parse(token.get());
        assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
        assertEquals("sherlock", jwt.getJWTClaimsSet().getSubject());
    }

    @Requires(property = "spec.name", value = "RSASignatureGeneratorTest")
    @Singleton
    static class MyRSASignatureGeneratorConfiguration implements RSASignatureGeneratorConfiguration {
        private final KeyPair keyPair;

        MyRSASignatureGeneratorConfiguration() throws NoSuchAlgorithmException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            this.keyPair = keyPairGenerator.generateKeyPair();
        }

        @Override
        public RSAPrivateKey getPrivateKey() {
            return (RSAPrivateKey) keyPair.getPrivate();
        }

        @Override
        public JWSAlgorithm getJwsAlgorithm() {
            return JWSAlgorithm.RS256;
        }

        @Override
        public RSAPublicKey getPublicKey() {
            return (RSAPublicKey) keyPair.getPublic();
        }
    }
}
