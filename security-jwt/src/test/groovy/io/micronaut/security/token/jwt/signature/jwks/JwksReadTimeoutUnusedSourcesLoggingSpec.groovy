package io.micronaut.security.token.jwt.signature.jwks

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import groovy.json.JsonOutput
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import org.slf4j.LoggerFactory
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.time.Duration
import java.time.Instant

class JwksReadTimeoutUnusedSourcesLoggingSpec extends Specification {

    void "unused JWKS ReadTimeout is not logged as ERROR"() {
        given:
        Logger logger = (Logger) LoggerFactory.getLogger(HttpClientJwksClient)
        Level previousLevel = logger.level
        boolean previousAdditive = logger.additive
        MemoryAppender appender = new MemoryAppender()
        logger.level = Level.DEBUG
        logger.additive = false
        logger.addAppender(appender)
        appender.start()

        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID('provider1')
                .generate()
        String jwksJson = JsonOutput.toJson(new JWKSet(rsaKey.toPublicJWK()).toJSONObject(false))
        String token = jwt(rsaKey)

        EmbeddedServer provider1 = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwksReadTimeoutUnusedSourcesLoggingSpecProvider1',
                'jwks.json' : jwksJson
        ])

        EmbeddedServer provider2 = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwksReadTimeoutUnusedSourcesLoggingSpecProvider2',
                'jwks.json' : jwksJson
        ])

        EmbeddedServer provider3 = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwksReadTimeoutUnusedSourcesLoggingSpecProvider3',
                'jwks.json' : jwksJson
        ])

        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwksReadTimeoutUnusedSourcesLoggingSpec',
                'micronaut.security.authentication': 'bearer',
                'micronaut.http.client.read-timeout': '50ms',
                'micronaut.http.client.pool.enabled': false,
                'micronaut.security.token.jwt.signatures.jwks.provider1.url': "http://localhost:${provider1.port}/keys",
                'micronaut.security.token.jwt.signatures.jwks.provider2.url': "http://localhost:${provider2.port}/keys",
                'micronaut.security.token.jwt.signatures.jwks.provider3.url': "http://localhost:${provider3.port}/keys",
                'micronaut.security.token.jwt.signatures.jwks.provider1.cache-expiration': 0,
                'micronaut.security.token.jwt.signatures.jwks.provider2.cache-expiration': 0,
                'micronaut.security.token.jwt.signatures.jwks.provider3.cache-expiration': 0,
        ])

        DefaultHttpClientConfiguration clientConfiguration = new DefaultHttpClientConfiguration(readTimeout: Duration.ofSeconds(5))
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL, clientConfiguration)
        def client = httpClient.toBlocking()

        when:
        String response = client.retrieve(HttpRequest.GET('/hello').bearerAuth(token))

        then:
        response == 'Hello'

        and:
        PollingConditions conditions = new PollingConditions(timeout: 3)
        conditions.eventually {
            assert !appender.contains(Level.ERROR, 'Exception loading JWK', 'io.micronaut.http.client.exceptions.ReadTimeoutException')
            assert appender.contains(Level.DEBUG, 'Read timeout loading JWK', 'io.micronaut.http.client.exceptions.ReadTimeoutException')
        }

        cleanup:
        logger.detachAppender(appender)
        logger.level = previousLevel
        logger.additive = previousAdditive

        server?.close()
        provider1?.close()
        provider2?.close()
        provider3?.close()
    }

    private static String jwt(RSAKey rsaKey) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject('123')
                .issuer('https://example.local')
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build()

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.keyID)
                .build()

        SignedJWT signedJWT = new SignedJWT(header, claimsSet)
        JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey())
        signedJWT.sign(signer)
        signedJWT.serialize()
    }

    static class MemoryAppender extends AppenderBase<ILoggingEvent> {
        final List<ILoggingEvent> events = []

        @Override
        protected void append(ILoggingEvent eventObject) {
            events << eventObject
        }

        void clear() {
            events.clear()
        }

        boolean contains(Level level, String messageContains, String throwableClassName) {
            events.any { ILoggingEvent e ->
                e.level == level &&
                        e.formattedMessage?.contains(messageContains) &&
                        e.throwableProxy?.className == throwableClassName
            }
        }
    }

    @Requires(property = 'spec.name', value = 'JwksReadTimeoutUnusedSourcesLoggingSpec')
    @Controller('/hello')
    static class HelloController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            'Hello'
        }
    }

    @Requires(property = 'spec.name', value = 'JwksReadTimeoutUnusedSourcesLoggingSpecProvider1')
    @Controller('/keys')
    static class Provider1KeysController {
        private final String jwksJson

        Provider1KeysController(Environment environment) {
            this.jwksJson = environment.getProperty('jwks.json', String).orElseThrow()
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String keys() {
            jwksJson
        }
    }

    @Requires(property = 'spec.name', value = 'JwksReadTimeoutUnusedSourcesLoggingSpecProvider2')
    @Controller('/keys')
    static class Provider2KeysController {
        private final String jwksJson

        Provider2KeysController(Environment environment) {
            this.jwksJson = environment.getProperty('jwks.json', String).orElseThrow()
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String keys() {
            sleep(250)
            jwksJson
        }
    }

    @Requires(property = 'spec.name', value = 'JwksReadTimeoutUnusedSourcesLoggingSpecProvider3')
    @Controller('/keys')
    static class Provider3KeysController {
        private final String jwksJson

        Provider3KeysController(Environment environment) {
            this.jwksJson = environment.getProperty('jwks.json', String).orElseThrow()
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String keys() {
            sleep(250)
            jwksJson
        }
    }
}
