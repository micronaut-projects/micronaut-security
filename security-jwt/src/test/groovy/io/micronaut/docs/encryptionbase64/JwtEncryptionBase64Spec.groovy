package io.micronaut.docs.encryptionbase64

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.DirectEncrypter
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.testutils.YamlAsciidocTagCleaner
import org.yaml.snakeyaml.Yaml

import java.nio.charset.StandardCharsets
import java.time.Instant

class JwtEncryptionBase64Spec extends ApplicationContextSpecification implements YamlAsciidocTagCleaner {

    private static final String BASE64_SECRET = 'cGxlYXNlQ2hhbmdlVGhpc1NlY3JldEZvckFOZXdPbmU='
    private static final String PLAIN_SECRET = 'pleaseChangeThisSecretForANewOne'

    private static final String yamlConfig = """
#tag::yamlconfig[]
micronaut:
  security:
    token:
      jwt:
        encryptions:
          secret:
            generator:
              secret: 'cGxlYXNlQ2hhbmdlVGhpc1NlY3JldEZvckFOZXdPbmU='
              base64: true
              jwe-algorithm: dir
              encryption-method: A256GCM
#end::yamlconfig[]
"""

    private static final Map<String, Object> configMap = [
            'micronaut': [
                    'security': [
                            'token': [
                                    'jwt': [
                                            'encryptions': [
                                                    'secret': [
                                                            'generator': [
                                                                    'secret': BASE64_SECRET,
                                                                    'base64': true,
                                                                    'jwe-algorithm': 'dir',
                                                                    'encryption-method': 'A256GCM'
                                                            ]
                                                    ]
                                            ]
                                    ]
                            ]
                    ]
            ]
    ]

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + flatten(configMap)
    }

    void "JWT encrypted with base64 encoded secret can be decrypted"() {
        given: 'YAML config matches map config and base64 decodes correctly'
        new Yaml().load(cleanYamlAsciidocTag(yamlConfig)) == configMap
        new String(BASE64_SECRET.decodeBase64()) == PLAIN_SECRET

        and:
        EncryptionConfiguration encryptionConfiguration = getBean(EncryptionConfiguration)

        when: 'create a JWT encrypted with the base64 decoded secret'
        byte[] decodedSecret = Base64.getDecoder().decode(BASE64_SECRET)
        EncryptedJWT jwt = createEncryptedJWT(decodedSecret)
        String token = jwt.serialize()

        then: 'the encrypted JWT can be decrypted using the EncryptionConfiguration'
        encryptionConfiguration.decrypt(EncryptedJWT.parse(token))
    }

    void "JWT encrypted with wrong secret fails decryption"() {
        given:
        EncryptionConfiguration encryptionConfiguration = getBean(EncryptionConfiguration)

        when: 'create a JWT encrypted with the plain text secret instead of base64 decoded'
        byte[] plainSecret = BASE64_SECRET.getBytes(StandardCharsets.UTF_8)
        EncryptedJWT jwt = createEncryptedJWT(plainSecret)
        String token = jwt.serialize()

        and: 'try to decrypt with our configured encrypter that expects base64-decoded secret'
        encryptionConfiguration.decrypt(EncryptedJWT.parse(token))

        then: 'decryption fails because the secrets do not match'
        thrown(JOSEException)
    }

    void "JWT encryption works with base64 disabled"() {
        given: 'configuration without base64 encoding'
        Map<String, Object> plainConfig = [
                'micronaut.security.token.jwt.encryptions.secret.generator.secret': PLAIN_SECRET,
                'micronaut.security.token.jwt.encryptions.secret.generator.base64': false,
                'micronaut.security.token.jwt.encryptions.secret.generator.jwe-algorithm': 'dir',
                'micronaut.security.token.jwt.encryptions.secret.generator.encryption-method': 'A256GCM',
        ]

        and:
        def ctx = io.micronaut.context.ApplicationContext.run(plainConfig)
        EncryptionConfiguration encryptionConfiguration = ctx.getBean(EncryptionConfiguration)

        when: 'create a JWT encrypted with the plain text secret'
        byte[] secretBytes = PLAIN_SECRET.getBytes(StandardCharsets.UTF_8)
        EncryptedJWT jwt = createEncryptedJWT(secretBytes)
        String token = jwt.serialize()

        then: 'the encrypted JWT can be decrypted'
        encryptionConfiguration.decrypt(EncryptedJWT.parse(token))

        cleanup:
        ctx?.close()
    }

    private EncryptedJWT createEncryptedJWT(byte[] secret) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("1234567890")
                .claim("name", "John Doe")
                .issueTime(Date.from(Instant.ofEpochSecond(1516239022)))
                .build()

        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
        EncryptedJWT jwt = new EncryptedJWT(header, claimsSet)
        DirectEncrypter encrypter = new DirectEncrypter(secret)
        jwt.encrypt(encrypter)
        return jwt
    }
}
