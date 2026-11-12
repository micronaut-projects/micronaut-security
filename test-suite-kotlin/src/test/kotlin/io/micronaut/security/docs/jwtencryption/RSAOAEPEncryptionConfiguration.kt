package io.micronaut.security.docs.jwtencryption

//tag::clazz[]
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryptionConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
//end::clazz[]

@Requires(property = "spec.name", value = "RSAOAEPEncryptionTest")
//tag::clazz[]

@Named("generator") // <1>
@Singleton
class RSAOAEPEncryptionConfiguration(@Value("\${pem.path}") pemPath: String) : RSAEncryptionConfiguration {

    private var rsaPrivateKey: RSAPrivateKey? = null
    private var rsaPublicKey: RSAPublicKey? = null
    private val jweAlgorithm = JWEAlgorithm.RSA_OAEP_256
    private val encryptionMethod = EncryptionMethod.A128GCM

    init {
        val keyPair = KeyPairProvider.keyPair(pemPath)
        if (keyPair.isPresent) {
            rsaPublicKey = keyPair.get().public as RSAPublicKey
            rsaPrivateKey = keyPair.get().private as RSAPrivateKey
        }
    }

    override fun getPublicKey(): RSAPublicKey? = rsaPublicKey

    override fun getPrivateKey(): RSAPrivateKey? = rsaPrivateKey

    override fun getJweAlgorithm(): JWEAlgorithm = jweAlgorithm

    override fun getEncryptionMethod(): EncryptionMethod = encryptionMethod
}
//end::clazz[]
