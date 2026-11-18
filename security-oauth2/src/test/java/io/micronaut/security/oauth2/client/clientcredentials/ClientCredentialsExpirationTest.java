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

    private final AdjustableClock clock = new AdjustableClock();

    @Test
    void tokenWithoutExpiresInOrExpClaimIsCachedForTheDefaultExpirationOfFiveMinutes() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(ClientCredentialsExpirationTest::opaqueToken);
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(NO_ADVANCED_EXPIRATION)
            .build());

        String accessToken = requestAccessToken(client);
        assertEquals(accessToken, requestAccessToken(client));

        clock.advance(Duration.ofMinutes(5).minusSeconds(1));
        assertEquals(accessToken, requestAccessToken(client));
        assertEquals(1, tokenEndpoint.requests());

        clock.advance(Duration.ofSeconds(2));
        assertNotEquals(accessToken, requestAccessToken(client));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void tokenWithoutExpiresInOrExpClaimIsRefreshedOnceTheConfiguredDefaultExpirationElapses() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(ClientCredentialsExpirationTest::opaqueToken);
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(NO_ADVANCED_EXPIRATION)
            .defaultExpiration(Duration.ofSeconds(90))
            .build());

        String accessToken = requestAccessToken(client);

        clock.advance(Duration.ofSeconds(89));
        assertEquals(accessToken, requestAccessToken(client));
        assertEquals(1, tokenEndpoint.requests());

        clock.advance(Duration.ofSeconds(2));
        assertNotEquals(accessToken, requestAccessToken(client));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void advancedExpirationIsSubtractedFromTheDefaultExpiration() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(ClientCredentialsExpirationTest::opaqueToken);
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(Duration.ofSeconds(30))
            .defaultExpiration(Duration.ofSeconds(90))
            .build());

        String accessToken = requestAccessToken(client);

        clock.advance(Duration.ofSeconds(59));
        assertEquals(accessToken, requestAccessToken(client));

        clock.advance(Duration.ofSeconds(2));
        assertNotEquals(accessToken, requestAccessToken(client));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void jwtAccessTokenWithoutExpiresInUsesTheExpClaimInsteadOfTheDefaultExpiration() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(() -> jwtToken(Duration.ofMinutes(2)));
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(NO_ADVANCED_EXPIRATION)
            .defaultExpiration(Duration.ofHours(1))
            .build());

        String accessToken = requestAccessToken(client);

        clock.advance(Duration.ofSeconds(110));
        assertEquals(accessToken, requestAccessToken(client));
        assertEquals(1, tokenEndpoint.requests());

        clock.advance(Duration.ofSeconds(20));
        assertNotEquals(accessToken, requestAccessToken(client));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void opaqueAccessTokenUsesExpiresInInsteadOfTheDefaultExpiration() {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(() -> {
            TokenResponse tokenResponse = opaqueToken();
            tokenResponse.setExpiresIn(120);
            return tokenResponse;
        });
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(NO_ADVANCED_EXPIRATION)
            .defaultExpiration(Duration.ofHours(1))
            .build());

        String accessToken = requestAccessToken(client);

        clock.advance(Duration.ofSeconds(110));
        assertEquals(accessToken, requestAccessToken(client));
        assertEquals(1, tokenEndpoint.requests());

        clock.advance(Duration.ofSeconds(20));
        assertNotEquals(accessToken, requestAccessToken(client));
        assertEquals(2, tokenEndpoint.requests());
    }

    @Test
    void expClaimEarlierThanExpiresInWins() {
        assertRefreshedAfterTwoMinutes(Duration.ofMinutes(2), 3600);
    }

    @Test
    void expiresInEarlierThanExpClaimWins() {
        assertRefreshedAfterTwoMinutes(Duration.ofHours(1), 120);
    }

    private void assertRefreshedAfterTwoMinutes(Duration jwtLifetime, int expiresIn) {
        StubTokenEndpointClient tokenEndpoint = new StubTokenEndpointClient(() -> {
            TokenResponse tokenResponse = jwtToken(jwtLifetime);
            tokenResponse.setExpiresIn(expiresIn);
            return tokenResponse;
        });
        ClientCredentialsClient client = client(tokenEndpoint, ClientCredentialsConfiguration.builder()
            .advancedExpiration(NO_ADVANCED_EXPIRATION)
            .build());

        String accessToken = requestAccessToken(client);

        clock.advance(Duration.ofSeconds(110));
        assertEquals(accessToken, requestAccessToken(client));
        assertEquals(1, tokenEndpoint.requests());

        clock.advance(Duration.ofSeconds(20));
        assertNotEquals(accessToken, requestAccessToken(client));
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

        assertEquals(4, accessTokens.stream().distinct().count());
        assertTrue(messages.stream().anyMatch(message -> message.contains("caching client credentials access token")));
        assertTrue(messages.stream().anyMatch(message -> message.contains("expired at")));
        assertTrue(messages.stream().anyMatch(message -> message.contains("cannot be parsed as a JWT")));
        assertTrue(messages.stream().allMatch(message -> message.contains("sha256 prefix")));
        for (String accessToken : accessTokens) {
            for (String secret : accessToken.split("\\.")) {
                assertFalse(messages.stream().anyMatch(message -> message.contains(secret)));
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
