package io.micronaut.security.token.jwt.signature.rsa

import com.nimbusds.jose.JWSAlgorithm
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.docs.signandencrypt.KeyPairProvider
import jakarta.inject.Named
import jakarta.inject.Singleton

import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@Named("generator")
@Requires(property = "spec.name", value = "signaturersa")
@Singleton
class PS512RSASignatureConfiguration implements RSASignatureGeneratorConfiguration {

    private RSAPrivateKey rsaPrivateKey
    private RSAPublicKey rsaPublicKey
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS512

    PS512RSASignatureConfiguration(@Value('${pem.path}') String pemPath) {
        Optional<KeyPair> keyPair = KeyPairProvider.keyPair(pemPath)
        if ( keyPair.isPresent() ) {
            this.rsaPublicKey = (RSAPublicKey) keyPair.get().getPublic()
            this.rsaPrivateKey = (RSAPrivateKey) keyPair.get().getPrivate()
        }
    }

    @Override
    JWSAlgorithm getJwsAlgorithm() {
        return jwsAlgorithm
    }

    @Override
    RSAPublicKey getPublicKey() {
        return rsaPublicKey
    }

    @Override
    RSAPrivateKey getPrivateKey() {
        return rsaPrivateKey
    }
}
