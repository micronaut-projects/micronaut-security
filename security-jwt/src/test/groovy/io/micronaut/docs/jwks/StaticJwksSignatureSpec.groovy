package io.micronaut.docs.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.testutils.YamlAsciidocTagCleaner
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import org.yaml.snakeyaml.Yaml
import spock.lang.Shared

import java.security.SecureRandom

class StaticJwksSignatureSpec extends ApplicationContextSpecification implements YamlAsciidocTagCleaner {

    String yamlConfig = """
#tag::yamlconfig[]
micronaut:
  security:
    token:
      jwt:
        signatures:
          jwks-static:
            google:
              path: 'classpath:jwks/certs.json'
#end::yamlconfig[]
"""

    private final static Map<String, Object> CONFIG_MAP = [
            'micronaut': [
                    'security': [
                            'token': [
                                    'jwt': [
                                            'signatures': [
                                                    'jwks-static': [
                                                            'google': [
                                                                    'path': 'classpath:jwks/certs.json'
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
        super.configuration + flatten(CONFIG_MAP)
    }

    void "SignatureConfiguration for static jwks gets registered"() {
        expect:
        new Yaml().load(cleanYamlAsciidocTag(yamlConfig)) == CONFIG_MAP
        applicationContext.containsBean(SignatureConfiguration.class, Qualifiers.byName("google"))

        when:
        SignatureConfiguration signatureConfiguration = applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("google"))

        then:
        !signatureConfiguration.supports(JWSAlgorithm.ES256)
        !signatureConfiguration.supports(JWSAlgorithm.HS256)
        !signatureConfiguration.supports(JWSAlgorithm.HS384)
        !signatureConfiguration.supports(JWSAlgorithm.HS512)
        signatureConfiguration.supports(JWSAlgorithm.RS256)
        !signatureConfiguration.supports(JWSAlgorithm.RS384)
        !signatureConfiguration.supports(JWSAlgorithm.RS512)
        !signatureConfiguration.supports(JWSAlgorithm.ES256)
        !signatureConfiguration.supports(JWSAlgorithm.ES256K)
        !signatureConfiguration.supports(JWSAlgorithm.ES384)
        !signatureConfiguration.supports(JWSAlgorithm.ES512)
        !signatureConfiguration.supports(JWSAlgorithm.PS256)
        !signatureConfiguration.supports(JWSAlgorithm.PS384)
        !signatureConfiguration.supports(JWSAlgorithm.PS512)
        !signatureConfiguration.supports(JWSAlgorithm.EdDSA)

        and:
        "Algorithms supported: RS256" == signatureConfiguration.supportedAlgorithmsMessage()

        and:
        !signatureConfiguration.verify(randomSignedJwt())
    }

    private static SignedJWT randomSignedJwt() {
        SecureRandom random = new SecureRandom()
        byte[] sharedSecret = new byte[32]
        random.nextBytes(sharedSecret)
        JWSSigner signer = new MACSigner(sharedSecret)
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload('{"username": "sherlock"}'))
        jwsObject.sign(signer)
        JWT jwt = JWTParser.parse(jwsObject.serialize())
        assert(jwt instanceof SignedJWT)
        (SignedJWT) jwt
    }
}
