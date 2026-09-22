package io.micronaut.security.docs.jwtgeneratorrsa

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGenerator
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.Specification

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@Property(name = "spec.name", value = "RSASignatureGeneratorTest")
@MicronautTest(startApplication = false)
class RSASignatureGeneratorTest extends Specification {

    @Inject
    @Named("generator")
    SignatureGeneratorConfiguration signatureGeneratorConfiguration

    @Inject
    TokenGenerator tokenGenerator

    void "tokens are signed with the RSA signature generator"() {
        expect:
        signatureGeneratorConfiguration instanceof RSASignatureGenerator

        when:
        Optional<String> token = tokenGenerator.generateToken(Authentication.build("sherlock"), 3600)

        then:
        token.isPresent()

        when:
        SignedJWT jwt = SignedJWT.parse(token.get())

        then:
        jwt.header.algorithm == JWSAlgorithm.RS256
        jwt.JWTClaimsSet.subject == "sherlock"
    }

    @Requires(property = "spec.name", value = "RSASignatureGeneratorTest")
    @Singleton
    static class MyRSASignatureGeneratorConfiguration implements RSASignatureGeneratorConfiguration {
        private final KeyPair keyPair

        MyRSASignatureGeneratorConfiguration() {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            this.keyPair = keyPairGenerator.generateKeyPair()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            (RSAPrivateKey) keyPair.private
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            JWSAlgorithm.RS256
        }

        @Override
        RSAPublicKey getPublicKey() {
            (RSAPublicKey) keyPair.public
        }
    }
}
