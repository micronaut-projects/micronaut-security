package io.micronaut.security.oauth2.client.clientcredentials

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.rules.SecurityRule
import org.slf4j.LoggerFactory
import reactor.core.publisher.Flux
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

class ClientCredentialsExpirationSpec extends Specification {

    @Shared
    @AutoCleanup
    EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'            : 'ClientCredentialsExpirationSpecAuthServer',
            'micronaut.server.port': -1,
    ])

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = ApplicationContext.run([
            'spec.name': 'ClientCredentialsExpirationSpec',
    ] + client('opaquedefault', 'opaque-default', null)
      + client('opaqueshort', 'opaque-short', '2s')
      + client('jwt', 'jwt', '1h')
      + client('logging', 'logging', '1s'))

    private Map<String, Object> client(String name, String path, String defaultExpiration) {
        Map<String, Object> m = [
                ("micronaut.security.oauth2.clients.${name}.token.url".toString())                               : "${authServer.URL}/token/${path}".toString(),
                ("micronaut.security.oauth2.clients.${name}.client-id".toString())                               : 'XXX',
                ("micronaut.security.oauth2.clients.${name}.client-secret".toString())                           : 'YYY',
                ("micronaut.security.oauth2.clients.${name}.client-credentials.advanced-expiration".toString())  : '0s',
        ]
        if (defaultExpiration) {
            m[("micronaut.security.oauth2.clients.${name}.client-credentials.default-expiration".toString())] = defaultExpiration
        }
        m
    }

    void "a token response without expires_in and without a JWT exp claim is cached for the default expiration of 5 minutes"() {
        given:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName('opaquedefault'))

        when:
        List<String> accessTokens = (1..5).collect { requestToken(clientCredentialsClient).accessToken }

        then:
        tokenController().requests('opaque-default') == 1
        accessTokens.unique().size() == 1

        when:
        Instant expiresAt = clientCredentialsClient.scopeToPublisherMap.values().collect { Flux.from(it).blockFirst().expiresAt() }.first()

        then:
        expiresAt.isAfter(Instant.now().plus(Duration.ofMinutes(4)))
        expiresAt.isBefore(Instant.now().plus(Duration.ofMinutes(5)).plusSeconds(1))
    }

    void "a token response without expires_in and without a JWT exp claim is refreshed once the configured default expiration elapses"() {
        given:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName('opaqueshort'))

        when:
        List<String> accessTokens = (1..5).collect { requestToken(clientCredentialsClient).accessToken }

        then:
        tokenController().requests('opaque-short') == 1
        accessTokens.unique().size() == 1

        when:
        sleep(2_500)
        List<String> refreshedTokens = (1..5).collect { requestToken(clientCredentialsClient).accessToken }

        then:
        tokenController().requests('opaque-short') == 2
        refreshedTokens.unique().size() == 1
        refreshedTokens.first() != accessTokens.first()
    }

    void "a JWT access token without expires_in uses the exp claim"() {
        given:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName('jwt'))

        when:
        List<String> accessTokens = (1..5).collect { requestToken(clientCredentialsClient).accessToken }

        then: 'the token is cached even though the token response has no expires_in'
        tokenController().requests('jwt') == 1
        accessTokens.unique().size() == 1

        when: 'the exp claim elapses, the token is refreshed even though default-expiration is one hour'
        sleep(3_500)
        String refreshed = requestToken(clientCredentialsClient).accessToken

        then:
        tokenController().requests('jwt') == 2
        refreshed != accessTokens.first()
    }

    void "access tokens are never written to the TRACE log"() {
        given:
        Logger logger = (Logger) LoggerFactory.getLogger(AbstractClientCredentialsClient)
        Level previousLevel = logger.level
        logger.level = Level.TRACE
        ListAppender<ILoggingEvent> appender = new ListAppender<>()
        appender.start()
        logger.addAppender(appender)
        ClientCredentialsClient loggingClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName('logging'))
        ClientCredentialsClient jwtClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName('jwt'))

        when:
        List<String> accessTokens = []
        accessTokens << requestToken(loggingClient).accessToken
        accessTokens << requestToken(loggingClient).accessToken
        sleep(1_500)
        accessTokens << requestToken(loggingClient).accessToken
        accessTokens << Flux.from(jwtClient.requestToken(true)).blockFirst().accessToken
        List<String> messages = appender.list.findAll { it.level == Level.TRACE }*.formattedMessage

        then:
        accessTokens.unique().size() == 3
        messages.any { it.contains('caching client credentials access token') }
        messages.any { it.contains('expired at') }
        messages.any { it.contains('cannot be parsed as a JWT') }
        messages.every { it.contains('sha256 prefix') }
        accessTokens.every { String token -> messages.every { String message -> !message.contains(token) } }
        accessTokens.findAll { it.contains('.') }.every { String jwt ->
            String payload = jwt.split('\\.')[1]
            messages.every { String message -> !message.contains(payload) }
        }

        cleanup:
        logger.detachAppender(appender)
        logger.level = previousLevel
    }

    private static TokenResponse requestToken(ClientCredentialsClient clientCredentialsClient) {
        Flux.from(clientCredentialsClient.requestToken()).blockFirst()
    }

    private TokenController tokenController() {
        authServer.applicationContext.getBean(TokenController)
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsExpirationSpecAuthServer')
    @Controller('/token')
    static class TokenController {
        private final Map<String, AtomicInteger> counters = new ConcurrentHashMap<>()

        int requests(String path) {
            counters.computeIfAbsent(path, k -> new AtomicInteger()).get()
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post('/{path}')
        Map<String, Object> token(String path) {
            counters.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet()
            String accessToken = path == 'jwt'
                    ? new PlainJWT(new JWTClaimsSet.Builder()
                        .subject('john')
                        .jwtID(UUID.randomUUID().toString())
                        .expirationTime(Date.from(Instant.now().plusSeconds(3)))
                        .build()).serialize()
                    : UUID.randomUUID().toString()
            [access_token: accessToken, token_type: 'bearer']
        }
    }
}
