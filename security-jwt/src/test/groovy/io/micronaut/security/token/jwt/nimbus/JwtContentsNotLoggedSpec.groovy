package io.micronaut.security.token.jwt.nimbus

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration
import io.micronaut.security.token.jwt.validator.JsonWebTokenSignatureValidator
import org.reactivestreams.Publisher
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

/**
 * Verifies that neither the compact serialization of a JWT nor the values of its claims are written to the logs.
 */
class JwtContentsNotLoggedSpec extends Specification {

    private static final String EMAIL = 'john.doe@example.com'

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = ApplicationContext.run([
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
    ])

    Logger securityLogger = (Logger) LoggerFactory.getLogger('io.micronaut.security')
    Level previousLevel
    ListAppender<ILoggingEvent> appender

    void setup() {
        previousLevel = securityLogger.level
        securityLogger.level = Level.TRACE
        appender = new ListAppender<>()
        appender.start()
        securityLogger.addAppender(appender)
    }

    void cleanup() {
        securityLogger.detachAppender(appender)
        appender.stop()
        securityLogger.level = previousLevel
    }

    private List<String> messages() {
        appender.list.collect { it.formattedMessage }
    }

    private static void assertNotLogged(List<String> messages, String token) {
        String[] parts = token.split('\\.')
        messages.each { String msg ->
            assert !msg.contains(token)
            assert !msg.contains(parts[1]) // payload segment
            assert !msg.contains(parts[2]) // signature segment
            assert !msg.contains(EMAIL)
        }
    }

    void "claims generation logs claim names but not claim values"() {
        given:
        JwtTokenGenerator tokenGenerator = applicationContext.getBean(JwtTokenGenerator)
        Authentication authentication = Authentication.build('sherlock', ['ROLE_DETECTIVE'], [email: EMAIL])

        when:
        String token = tokenGenerator.generateToken(authentication, 3600).get()

        then:
        token
        messages().any { it.startsWith('Generated claim set with claims:') && it.contains('email') && it.contains('sub') }
        assertNotLogged(messages(), token)
    }

    void "signature validator does not log the token when verification fails"() {
        given:
        JwtTokenGenerator tokenGenerator = applicationContext.getBean(JwtTokenGenerator)
        JsonWebTokenSignatureValidator<SignedJWT> signatureValidator = applicationContext.getBean(JsonWebTokenSignatureValidator)
        Authentication authentication = Authentication.build('sherlock', ['ROLE_DETECTIVE'], [email: EMAIL])
        String token = tokenGenerator.generateToken(authentication, 3600).get()
        String[] parts = token.split('\\.')
        String tampered = parts[0] + '.' + parts[1] + '.' + parts[2].reverse()
        appender.list.clear()

        when:
        boolean valid = signatureValidator.validateSignature(SignedJWT.parse(tampered))

        then:
        !valid
        messages().any { it.startsWith('Signature verification failed for JWT [kid=') && it.contains('alg=HS256') }
        assertNotLogged(messages(), token)
        assertNotLogged(messages(), tampered)
    }

    void "reactive JWKS signature does not log the token whether or not verification succeeds"() {
        given:
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID('kid-1').generate()
        RSAKey otherKey = new RSAKeyGenerator(2048).keyID('kid-1').generate()
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK())
        JwksSignatureConfiguration configuration = new JwksSignatureConfiguration() {
            @Override
            String getUrl() { 'http://localhost/.well-known/jwks.json' }

            @Override
            KeyType getKeyType() { KeyType.RSA }

            @Override
            Integer getCacheExpiration() { 60 }

            @Override
            String getName() { 'test' }
        }
        JwkSetFetcher<JWKSet> fetcher = new JwkSetFetcher<JWKSet>() {
            @Override
            Publisher<JWKSet> fetch(String providerName, String url) { Mono.just(jwkSet) }

            @Override
            void clearCache(String url) { }
        }
        ReactiveJwksSignature signature = new ReactiveJwksSignature(configuration, applicationContext.getBean(JwkValidator), fetcher)
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject('sherlock').jwtID('jti-123').claim('email', EMAIL).build()
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID('kid-1').build()
        SignedJWT validJwt = new SignedJWT(header, claims)
        validJwt.sign(new RSASSASigner(rsaKey))
        SignedJWT invalidJwt = new SignedJWT(header, claims)
        invalidJwt.sign(new RSASSASigner(otherKey))

        when:
        boolean valid = Mono.from(signature.verify(validJwt)).block()
        boolean invalid = Mono.from(signature.verify(invalidJwt)).block()

        then:
        valid
        !invalid
        messages().any { it == 'Signature verified for JWT [kid=kid-1, alg=RS256, jti=jti-123]' }
        messages().any { it == 'Signature not verified for JWT [kid=kid-1, alg=RS256, jti=jti-123]' }
        assertNotLogged(messages(), validJwt.serialize())
        assertNotLogged(messages(), invalidJwt.serialize())
    }
}
