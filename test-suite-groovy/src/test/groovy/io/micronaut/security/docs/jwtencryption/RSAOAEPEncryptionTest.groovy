package io.micronaut.security.docs.jwtencryption

import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTParser
import io.micronaut.context.annotation.Property
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryption
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Named
import reactor.core.publisher.Mono
import spock.lang.Specification

@Property(name = "spec.name", value = "RSAOAEPEncryptionTest")
@Property(name = "pem.path", value = "src/test/resources/rsa-2048bit-key-pair.pem")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest(startApplication = false)
class RSAOAEPEncryptionTest extends Specification {

    @Inject
    @Named("generator")
    EncryptionConfiguration encryptionConfiguration

    @Inject
    TokenGenerator tokenGenerator

    @Inject
    TokenValidator tokenValidator

    void "tokens are encrypted with the RSA key pair"() {
        expect:
        encryptionConfiguration instanceof RSAEncryption

        when:
        Optional<String> token = tokenGenerator.generateToken(Authentication.build("sherlock"), 3600)

        then:
        token.isPresent()
        JWTParser.parse(token.get()) instanceof EncryptedJWT

        when:
        Authentication authentication = Mono.from(tokenValidator.validateToken(token.get(), null)).block()

        then:
        authentication
        authentication.name == "sherlock"
    }
}
