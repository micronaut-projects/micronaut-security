package io.micronaut.security.token.jwt.signature.rsa

import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.AuthorizationUtils
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration
import io.micronaut.security.testutils.EmbeddedServerSpecification

class SignRSANotEncrypSpec extends EmbeddedServerSpecification implements AuthorizationUtils {

    @Override
    String getSpecName() {
        'signaturersa'
    }

    private static final File pemFile = new File('src/test/resources/rsa-2048bit-key-pair.pem')

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
                'pem.path': pemFile.absolutePath,
                'micronaut.security.authentication'   : 'bearer',
        ]
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
        embeddedServer.applicationContext.getBean(PS512RSASignatureConfiguration.class)
        embeddedServer.applicationContext.getBean(RSASignatureConfiguration.class)
        embeddedServer.applicationContext.getBean(RSASignatureConfiguration.class, Qualifiers.byName("generator"))
        embeddedServer.applicationContext.getBean(RSASignatureGeneratorConfiguration.class)
        embeddedServer.applicationContext.getBean(RSASignatureGeneratorConfiguration.class, Qualifiers.byName("generator"))
        embeddedServer.applicationContext.getBean(RSASignatureFactory.class)
        embeddedServer.applicationContext.getBean(SignatureConfiguration.class)
        embeddedServer.applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))
        embeddedServer.applicationContext.getBean(SignatureGeneratorConfiguration.class)
        embeddedServer.applicationContext.getBean(SignatureGeneratorConfiguration.class, Qualifiers.byName("generator"))
        embeddedServer.applicationContext.getBean(TokenGenerator.class)

        when:
        embeddedServer.applicationContext.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        JwtTokenGenerator tokenGenerator = embeddedServer.applicationContext.getBean(JwtTokenGenerator.class)

        then:
        tokenGenerator.getSignatureConfiguration() instanceof RSASignature
        tokenGenerator.getSignatureConfiguration() instanceof RSASignatureGenerator

        when:
        String token = loginWith(client,'user', 'password')

        then:
        token
        !(JWTParser.parse(token) instanceof EncryptedJWT)
        JWTParser.parse(token) instanceof SignedJWT

        when:
        get("/beans", token)

        then:
        noExceptionThrown()
    }
}
