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
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@Property(name = "spec.name", value = "RSASignatureGeneratorTest")
@MicronautTest(startApplication = false)
internal class RSASignatureGeneratorTest {

    @Test
    fun tokensAreSignedWithTheRsaSignatureGenerator(@Named("generator") signatureGeneratorConfiguration: SignatureGeneratorConfiguration,
                                                    tokenGenerator: TokenGenerator) {
        assertInstanceOf(RSASignatureGenerator::class.java, signatureGeneratorConfiguration)
        val token = tokenGenerator.generateToken(Authentication.build("sherlock"), 3600)
        assertTrue(token.isPresent)
        val jwt = SignedJWT.parse(token.get())
        assertEquals(JWSAlgorithm.RS256, jwt.header.algorithm)
        assertEquals("sherlock", jwt.jwtClaimsSet.subject)
    }

    @Requires(property = "spec.name", value = "RSASignatureGeneratorTest")
    @Singleton
    internal class MyRSASignatureGeneratorConfiguration : RSASignatureGeneratorConfiguration {
        private val keyPair: KeyPair

        init {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPair = keyPairGenerator.generateKeyPair()
        }

        override fun getPrivateKey(): RSAPrivateKey = keyPair.private as RSAPrivateKey

        override fun getJwsAlgorithm(): JWSAlgorithm = JWSAlgorithm.RS256

        override fun getPublicKey(): RSAPublicKey = keyPair.public as RSAPublicKey
    }
}
