package io.micronaut.security.oauth2.endpoint.token.response.validation

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.nimbusds.jwt.JWT
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono

import java.time.Instant

/**
 * Verifies that a nonce mismatch is reported at WARN level naming the failing validator and the claim names,
 * without writing the ID token or any claim value to the logs.
 */
class OpenIdTokenResponseValidatorNonceMismatchLoggingSpec extends ApplicationContextSpecification {

    private static final String EMAIL = 'john.doe@example.com'
    private static final String ISSUER = 'https://issuer.example.com'
    private static final String CLIENT_ID = 'client-id'

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]
    }

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

    void "nonce mismatch is logged at WARN with claim names only"() {
        given:
        JwtTokenGenerator tokenGenerator = applicationContext.getBean(JwtTokenGenerator)
        ReactiveOpenIdTokenResponseValidator<JWT> validator = applicationContext.getBean(ReactiveOpenIdTokenResponseValidator)
        String idToken = tokenGenerator.generateToken([
                iss  : ISSUER,
                aud  : CLIENT_ID,
                sub  : 'sherlock',
                email: EMAIL,
                nonce: 'expected-nonce',
                exp  : Instant.now().plusSeconds(3600).epochSecond,
        ]).get()
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse()
        tokenResponse.idToken = idToken
        OauthClientConfiguration clientConfiguration = Stub(OauthClientConfiguration) {
            getClientId() >> CLIENT_ID
            getName() >> 'myprovider'
        }
        OpenIdProviderMetadata providerMetadata = Stub(OpenIdProviderMetadata) {
            getIssuer() >> ISSUER
            getJwksUri() >> (ISSUER + '/jwks')
        }
        appender.list.clear()

        when:
        Optional<JWT> result = Mono.from(validator.validate(clientConfiguration, providerMetadata, tokenResponse, 'a-different-nonce')).blockOptional()

        then:
        result.isEmpty()

        when:
        List<ILoggingEvent> warnings = appender.list.findAll { it.level == Level.WARN }

        then:
        warnings.size() == 1
        warnings[0].formattedMessage.startsWith('NonceClaimValidator failed for provider [myprovider].')
        warnings[0].formattedMessage.contains('email')
        warnings[0].formattedMessage.contains('nonce')
        !appender.list.any { it.level == Level.ERROR }

        and: 'neither the ID token nor any claim value is logged'
        String[] parts = idToken.split('\\.')
        appender.list.every { ILoggingEvent event ->
            String msg = event.formattedMessage
            !msg.contains(idToken) && !msg.contains(parts[1]) && !msg.contains(EMAIL) && !msg.contains('expected-nonce') && !msg.contains('a-different-nonce')
        }
    }
}
