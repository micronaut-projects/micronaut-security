package io.micronaut.docs.signandencrypt

import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTParser
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.AuthorizationUtils
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.encryption.rsa.RSAEncryption
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.signature.secret.SecretSignature
import io.micronaut.testutils.EmbeddedServerSpecification
import io.micronaut.testutils.YamlAsciidocTagCleaner
import org.yaml.snakeyaml.Yaml

class SignSecretEncryptRSASpec extends EmbeddedServerSpecification implements AuthorizationUtils, YamlAsciidocTagCleaner {

    private final static String yamlConfig = """
#tag::yamlconfig[]
micronaut:
  security:
    token:
      jwt:
        signatures:
          secret:
            generator: 
              secret: pleaseChangeThisSecretForANewOne #<1>
              jws-algorithm: HS256 # <2>
#end::yamlconfig[]
"""

    private final static File pemFile = new File('src/test/resources/rsa-2048bit-key-pair.pem')

    private final static Map<String, Object> configMap = [
            'micronaut': [
                    'security': [
                            'token': [
                                    'jwt': [
                                        'signatures': [
                                                'secret': [
                                                        'generator': [
                                                                'secret': 'pleaseChangeThisSecretForANewOne',
                                                                'jws-algorithm': 'HS256'
                                                        ]
                                                ]
                                        ]
                                    ]
                            ]
                    ]
            ]
    ]

    @Override
    String getSpecName() {
        'signandencrypt'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
                'pem.path': pemFile.absolutePath,
                'micronaut.security.login-handler': 'bearer',
        ] << flatten(configMap)
    }

    void "test /beans is secured"() {
        when:
        get("/beans")

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "/beans can be accessed if authenticated"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlConfig)) == configMap
        embeddedServer.applicationContext.getBean(RSAOAEPEncryptionConfiguration.class)
        embeddedServer.applicationContext.getBean(SignatureConfiguration.class)
        embeddedServer.applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))
        embeddedServer.applicationContext.getBean(EncryptionConfiguration.class, Qualifiers.byName("generator"))
        embeddedServer.applicationContext.getBean(TokenGenerator.class)

        when:
        JwtTokenGenerator tokenGenerator = embeddedServer.applicationContext.getBean(JwtTokenGenerator.class)

        then:
        tokenGenerator.getSignatureConfiguration() instanceof SecretSignature
        tokenGenerator.getEncryptionConfiguration() instanceof RSAEncryption

        when:
        String token = loginWith(client,'user', 'password')

        then:
        token

        and:
        JWTParser.parse(token) instanceof EncryptedJWT

        when:
        get("/beans", token)

        then:
        noExceptionThrown()
    }
}
