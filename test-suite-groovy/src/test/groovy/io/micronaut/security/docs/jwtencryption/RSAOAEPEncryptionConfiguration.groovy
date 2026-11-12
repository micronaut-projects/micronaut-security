package io.micronaut.security.docs.jwtencryption

//tag::clazz[]
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryptionConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton

import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
//end::clazz[]

@Requires(property = "spec.name", value = "RSAOAEPEncryptionTest")
//tag::clazz[]

@Named("generator") // <1>
@Singleton
class RSAOAEPEncryptionConfiguration implements RSAEncryptionConfiguration {

    private RSAPrivateKey rsaPrivateKey
    private RSAPublicKey rsaPublicKey
    JWEAlgorithm jweAlgorithm = JWEAlgorithm.RSA_OAEP_256
    EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM

    RSAOAEPEncryptionConfiguration(@Value('${pem.path}') String pemPath) {
        Optional<KeyPair> keyPair = KeyPairProvider.keyPair(pemPath)
        if (keyPair.isPresent()) {
            this.rsaPublicKey = (RSAPublicKey) keyPair.get().getPublic()
            this.rsaPrivateKey = (RSAPrivateKey) keyPair.get().getPrivate()
        }
    }

    @Override
    RSAPublicKey getPublicKey() {
        rsaPublicKey
    }

    @Override
    RSAPrivateKey getPrivateKey() {
        rsaPrivateKey
    }

    @Override
    JWEAlgorithm getJweAlgorithm() {
        jweAlgorithm
    }

    @Override
    EncryptionMethod getEncryptionMethod() {
        encryptionMethod
    }
}
//end::clazz[]
