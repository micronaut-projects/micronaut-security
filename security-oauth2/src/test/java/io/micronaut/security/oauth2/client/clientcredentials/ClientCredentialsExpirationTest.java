package io.micronaut.security.oauth2.client.clientcredentials;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientCredentialsExpirationTest {

    private static final Duration NO_ADVANCED_EXPIRATION = Duration.ZERO;
    private static final Duration TOLERANCE = Duration.ofSeconds(10);

    private final AdjustableClock clock = new AdjustableClock();

    @Test
    void tokenWithoutExpiresInOrExpClaimIsCachedForTheDefaultExpirationOfFiveMinutes() {
        assertCachedFor(Duration.ofMinutes(5), ClientCredentialsExpirationTest::opaqueToken,
            ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION));
    }

    @Test
    void tokenWithoutExpiresInOrExpClaimIsCachedForTheConfiguredDefaultExpiration() {
        assertCachedFor(Duration.ofSeconds(90), ClientCredentialsExpirationTest::opaqueToken,
            ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION).defaultExpiration(Duration.ofSeconds(90)));
    }

    @Test
    void advancedExpirationIsSubtractedFromTheDefaultExpiration() {
        assertCachedFor(Duration.ofSeconds(60), ClientCredentialsExpirationTest::opaqueToken,
            ClientCredentialsConfiguration.builder().advancedExpiration(Duration.ofSeconds(30)).defaultExpiration(Duration.ofSeconds(90)));
    }

    @Test
    void jwtAccessTokenWithoutExpiresInUsesTheExpClaimInsteadOfTheDefaultExpiration() {
        assertCachedFor(Duration.ofMinutes(2), () -> jwtToken(Duration.ofMinutes(2)),
            ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION).defaultExpiration(Duration.ofHours(1)));
    }

    @Test
    void opaqueAccessTokenUsesExpiresInInsteadOfTheDefaultExpiration() {
        assertCachedFor(Duration.ofMinutes(2), () -> withExpiresIn(opaqueToken(), 120),
            ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION).defaultExpiration(Duration.ofHours(1)));
    }

    @Test
    void expClaimEarlierThanExpiresInWins() {
        assertCachedFor(Duration.ofMinutes(2), () -> withExpiresIn(jwtToken(Duration.ofMinutes(2)), 3600),
            ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION));
    }

    @Test
    void expiresInEarlierThanExpClaimWins() {
        assertCachedFor(Duration.ofMinutes(2), () -> withExpiresIn(jwtToken(Duration.ofHours(1)), 120),
            ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION));
    }

    /**
     * Asserts that a token is served from the cache until shortly before {@code lifetime} elapses and requested again shortly after.
     */
    private void assertCachedFor(Duration lifetime,
                                 Supplier<TokenResponse> tokenResponses,
                                 ClientCredentialsConfigurationBuilder clientCredentialsConfiguration) {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(tokenResponses);
        ClientCredentialsClient client = client(tokenEndpoint, clientCredentialsConfiguration.build());
        String accessToken = requestAccessToken(client);
        assertEquals(accessToken, requestAccessToken(client), "the token is cached right after it is obtained");

        clock.advance(lifetime.minus(TOLERANCE));
        assertEquals(accessToken, requestAccessToken(client), "the token is still cached shortly before " + lifetime + " elapses");
        assertEquals(1, tokenEndpoint.requests());

        clock.advance(TOLERANCE.multipliedBy(2));
        assertNotEquals(accessToken, requestAccessToken(client), "the token is refreshed once " + lifetime + " elapses");
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void callersWhichObserveTheSameExpiredTokenShareASingleTokenRequest() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(ClientCredentialsExpirationTest::opaqueToken);
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(NO_ADVANCED_EXPIRATION)
            .build());
        String accessToken = requestAccessToken(client);
        clock.advance(Duration.ofMinutes(6));

        List<Publisher<TokenResponse>> concurrentRequests = List.of(client.requestToken(), client.requestToken(), client.requestToken());
        List<String> refreshed = concurrentRequests.stream()
            .map(request -> Mono.from(request).map(TokenResponse::getAccessToken).block())
            .distinct()
            .toList();

        assertEquals(1, refreshed.size());
        assertNotEquals(accessToken, refreshed.get(0));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void forcedRequestBypassesTheCache() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(ClientCredentialsExpirationTest::opaqueToken);
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder().build());

        String accessToken = requestAccessToken(client);
        String forced = Mono.from(client.requestToken(true)).map(TokenResponse::getAccessToken).block();

        assertNotEquals(accessToken, forced);
        assertEquals(forced, requestAccessToken(client));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void accessTokensAreNeverWrittenToTheTraceLog() {
        Logger logger = (Logger) LoggerFactory.getLogger(AbstractClientCredentialsClient.class);
        Level previousLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.setLevel(Level.TRACE);
        logger.addAppender(appender);
        List<String> accessTokens = new ArrayList<>();
        try {
            ClientCredentialsClient opaqueClient = client(new StubTokenEndpointClient(ClientCredentialsExpirationTest::opaqueToken),
                ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION).build());
            ClientCredentialsClient jwtClient = client(new StubTokenEndpointClient(() -> jwtToken(Duration.ofMinutes(2))),
                ClientCredentialsConfiguration.builder().advancedExpiration(NO_ADVANCED_EXPIRATION).build());
            accessTokens.add(requestAccessToken(opaqueClient));
            accessTokens.add(requestAccessToken(jwtClient));
            clock.advance(Duration.ofMinutes(6));
            accessTokens.add(requestAccessToken(opaqueClient));
            accessTokens.add(requestAccessToken(jwtClient));
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
        }
        List<String> messages = appender.list.stream()
            .filter(event -> event.getLevel() == Level.TRACE)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();

        assertEquals(4, accessTokens.stream().distinct().count(), "every request obtained a new token");
        assertTrue(messages.stream().anyMatch(message -> message.contains("caching client credentials access token")), "caching is traced");
        assertTrue(messages.stream().anyMatch(message -> message.contains("expired at")), "expiration is traced");
        assertTrue(messages.stream().anyMatch(message -> message.contains("cannot be parsed as a JWT")), "opaque tokens are traced");
        assertTrue(messages.stream().allMatch(message -> message.contains("sha256 prefix")), "tokens are identified by fingerprint");
        for (String accessToken : accessTokens) {
            for (String secret : accessToken.split("\\.")) {
                assertFalse(messages.stream().anyMatch(message -> message.contains(secret)), "no token or JWT segment is traced");
            }
        }
    }

    private ClientCredentialsClient client(TokenEndpointClient tokenEndpointClient,
                                           ClientCredentialsConfiguration clientCredentialsConfiguration) {
        OauthClientConfiguration configuration = OauthClientConfiguration.builder()
            .name("auth-server")
            .clientId("client-id")
            .clientSecret("client-secret")
            .token("https://auth.example.com/token")
            .clientCredentialsConfiguration(clientCredentialsConfiguration)
            .build();
        return new AbstractClientCredentialsClient(configuration, tokenEndpointClient, clock) {
            @Override
            protected ClientCredentialsTokenRequestContext createTokenRequestContext(String scope) {
                return new ClientCredentialsTokenRequestContext(scope, oauthClientConfiguration);
            }
        };
    }

    private static String requestAccessToken(ClientCredentialsClient client) {
        return Mono.from(client.requestToken()).map(TokenResponse::getAccessToken).block();
    }

    private static TokenResponse opaqueToken() {
        return new TokenResponse(UUID.randomUUID().toString(), "bearer");
    }

    private static TokenResponse withExpiresIn(TokenResponse tokenResponse, int expiresIn) {
        tokenResponse.setExpiresIn(expiresIn);
        return tokenResponse;
    }

    private static TokenResponse jwtToken(Duration lifetime) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("john")
            .jwtID(UUID.randomUUID().toString())
            .expirationTime(Date.from(Instant.now().plus(lifetime)))
            .build();
        return new TokenResponse(new PlainJWT(claims).serialize(), "bearer");
    }

    /**
     * Counts the token requests and answers each one with a new token response.
     */
    private static final class StubTokenEndpointClient implements TokenEndpointClient {
        private final Supplier<TokenResponse> tokenResponses;
        private final AtomicInteger requests = new AtomicInteger();

        private StubTokenEndpointClient(Supplier<TokenResponse> tokenResponses) {
            this.tokenResponses = tokenResponses;
        }

        int requests() {
            return requests.get();
        }

        @Override
        @SuppressWarnings("unchecked")
        public <G, R extends TokenResponse> Publisher<R> sendRequest(TokenRequestContext<G, R> requestContext) {
            return Mono.fromSupplier(() -> {
                requests.incrementAndGet();
                return (R) tokenResponses.get();
            });
        }
    }

    /**
     * The system clock shifted by an offset, so that it stays consistent with the dates
     * {@link TokenResponse#setExpiresIn(Integer)} and the JWT {@code exp} claim derive from the system time.
     */
    private static final class AdjustableClock extends Clock {
        private Duration offset = Duration.ZERO;

        void advance(Duration duration) {
            offset = offset.plus(duration);
        }

        @Override
        public Instant instant() {
            return Instant.now().plus(offset);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
