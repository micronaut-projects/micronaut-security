package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.time.Instant
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Verifies that when a JWT carries a kid which is not present in the cached JWKS, the JWKS is fetched again (rate limited)
 * without waiting for the cache to expire.
 */
class JwksRefreshOnUnknownKidSpec extends Specification {

    private static final Map<String, Object> REACTOR_CACHE = [:]
    private static final Map<String, Object> MICRONAUT_CACHE = ['micronaut.caches.jwks.expire-after-write': '1h']

    @AutoCleanup
    @Shared
    EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name': 'JwksRefreshOnUnknownKidSpecAuthServer',
    ])

    private EmbeddedServer startServer(Map<String, Object> extra) {
        ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'JwksRefreshOnUnknownKidSpec',
                'micronaut.http.client.read-timeout': '30s',
                'micronaut.security.authentication': 'bearer',
                'micronaut.security.token.jwt.signatures.jwks.rotating.url': "http://localhost:${authServer.port}/jwks".toString(),
                'micronaut.security.token.jwt.signatures.jwks.rotating.cache-expiration': 3600,
        ] + extra)
    }

    private RotatingKeys keys() {
        authServer.applicationContext.getBean(RotatingKeys)
    }

    void "a token signed with a rotated kid is accepted after exactly one extra JWKS fetch without waiting for cache expiry (#description)"(Map<String, Object> cacheConfig, String description) {
        given:
        RotatingKeys keys = keys()
        keys.reset()
        EmbeddedServer server = startServer(cacheConfig)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when: 'a token signed with the current key is used'
        String token = sign(keys.current)

        then: 'JWKS are fetched once'
        hello(client, token) == HttpStatus.OK
        keys.invocations.get() == 1

        when: 'the same token is used again'
        hello(client, token)

        then: 'JWKS are cached'
        keys.invocations.get() == 1

        when: 'the authorization server rotates its key and issues a token with the new kid'
        RSAKey rotated = keys.rotate()
        String rotatedToken = sign(rotated)

        then: 'the token is accepted and the JWKS was fetched exactly once more'
        hello(client, rotatedToken) == HttpStatus.OK
        keys.invocations.get() == 2

        when: 'the rotated token is used again'
        hello(client, rotatedToken)

        then: 'the refreshed JWKS is cached'
        keys.invocations.get() == 2

        cleanup:
        httpClient.close()
        server.close()

        where:
        cacheConfig     | description
        REACTOR_CACHE   | 'reactor cache'
        MICRONAUT_CACHE | 'micronaut cache'
    }

    void "a token with an unknown kid triggers at most one JWKS fetch within the refresh interval even with several requests (#description)"(Map<String, Object> cacheConfig, String description) {
        given:
        RotatingKeys keys = keys()
        keys.reset()
        EmbeddedServer server = startServer(cacheConfig)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        RSAKey unknownKey = generateKey('unknown-kid')
        String unknownToken = sign(unknownKey)

        when: 'JWKS are warmed up'
        hello(client, sign(keys.current))

        then:
        keys.invocations.get() == 1

        when: 'several sequential requests with an unknown kid arrive'
        List<HttpStatus> statuses = (1..5).collect { hello(client, unknownToken) }

        then: 'they are all rejected and the JWKS was fetched only once more'
        statuses.every { it == HttpStatus.UNAUTHORIZED }
        keys.invocations.get() == 2

        when: 'a burst of concurrent requests with an unknown kid arrives'
        ExecutorService executor = Executors.newFixedThreadPool(8)
        List<Future<HttpStatus>> futures = (1..16).collect { executor.submit({ hello(client, unknownToken) } as Callable<HttpStatus>) }
        List<HttpStatus> burstStatuses = futures.collect { it.get(30, TimeUnit.SECONDS) }
        executor.shutdown()

        then: 'they are all rejected and no additional JWKS fetch happened'
        burstStatuses.every { it == HttpStatus.UNAUTHORIZED }
        keys.invocations.get() == 2

        when: 'a token with a known kid but an invalid signature is used'
        String forgedToken = sign(generateKey(keys.current.keyID))

        then: 'it is rejected and no refresh is triggered because the kid is present in the cached JWKS'
        hello(client, forgedToken) == HttpStatus.UNAUTHORIZED
        keys.invocations.get() == 2

        cleanup:
        httpClient.close()
        server.close()

        where:
        cacheConfig     | description
        REACTOR_CACHE   | 'reactor cache'
        MICRONAUT_CACHE | 'micronaut cache'
    }

    void "the refresh interval is configurable"() {
        given:
        RotatingKeys keys = keys()
        keys.reset()
        EmbeddedServer server = startServer(['micronaut.security.token.jwt.signatures.jwks.rotating.refresh-interval': '1s'])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        String unknownToken = sign(generateKey('unknown-kid'))

        expect:
        server.applicationContext.getBean(JwksSignatureConfiguration).refreshInterval.toSeconds() == 1

        when:
        hello(client, sign(keys.current))
        hello(client, unknownToken)

        then:
        keys.invocations.get() == 2

        when: 'another request with an unknown kid arrives within the refresh interval'
        hello(client, unknownToken)

        then:
        keys.invocations.get() == 2

        when: 'the refresh interval elapses'
        sleep(1_500)
        hello(client, unknownToken)

        then: 'the JWKS may be refreshed again'
        keys.invocations.get() == 3

        cleanup:
        httpClient.close()
        server.close()
    }

    void "a token without kid does not trigger a JWKS refresh"() {
        given:
        RotatingKeys keys = keys()
        keys.reset()
        EmbeddedServer server = startServer([:])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when: 'JWKS are warmed up'
        hello(client, sign(keys.current))

        then:
        keys.invocations.get() == 1

        when: 'a token without kid signed with an unknown key is used'
        String tokenWithoutKid = sign(generateKey('other'), false)

        then: 'it is rejected and JWKS are not fetched again'
        hello(client, tokenWithoutKid) == HttpStatus.UNAUTHORIZED
        keys.invocations.get() == 1

        when: 'a token without kid signed with the current key is used'
        String validTokenWithoutKid = sign(keys.current, false)

        then: 'it is accepted with the cached JWKS'
        hello(client, validTokenWithoutKid) == HttpStatus.OK
        keys.invocations.get() == 1

        cleanup:
        httpClient.close()
        server.close()
    }

    private static HttpStatus hello(BlockingHttpClient client, String token) {
        try {
            return client.exchange(HttpRequest.GET('/hello').bearerAuth(token), String).status()
        } catch (HttpClientResponseException e) {
            return e.status
        }
    }

    private static RSAKey generateKey(String kid) {
        new RSAKeyGenerator(2048)
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(kid)
                .generate()
    }

    private static String sign(RSAKey rsaKey, boolean includeKid = true) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject('sherlock')
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build()
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256)
        if (includeKid) {
            header = header.keyID(rsaKey.keyID)
        }
        SignedJWT signedJWT = new SignedJWT(header.build(), claimsSet)
        signedJWT.sign(new RSASSASigner(rsaKey.toPrivateKey()))
        signedJWT.serialize()
    }

    @Requires(property = 'spec.name', value = 'JwksRefreshOnUnknownKidSpec')
    @Controller("/hello")
    static class HelloWorldController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        @Secured(SecurityRule.IS_AUTHENTICATED)
        String index() {
            'Hello World'
        }
    }

    @Requires(property = 'spec.name', value = 'JwksRefreshOnUnknownKidSpecAuthServer')
    @Singleton
    static class RotatingKeys {
        final AtomicInteger invocations = new AtomicInteger()
        volatile RSAKey current = generateKey('kid-0')
        private int generation = 0

        RSAKey rotate() {
            current = generateKey('kid-' + (++generation))
            current
        }

        void reset() {
            invocations.set(0)
            rotate()
        }
    }

    @Requires(property = 'spec.name', value = 'JwksRefreshOnUnknownKidSpecAuthServer')
    @Controller("/jwks")
    static class JwksController {
        private final RotatingKeys keys

        JwksController(RotatingKeys keys) {
            this.keys = keys
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.APPLICATION_JSON)
        @Get
        String index() {
            keys.invocations.incrementAndGet()
            new JWKSet(keys.current.toPublicJWK()).toString()
        }
    }
}
