package io.micronaut.security.oauth2.client;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.scheduler.NonBlocking;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises the memoization, the back-off and the non-blocking thread behavior of {@link DefaultOpenIdProviderMetadataFetcher}
 * without waiting for the default back-off.
 */
class DefaultOpenIdProviderMetadataFetcherTest {
    private static final String SPEC_NAME = "DefaultOpenIdProviderMetadataFetcherTest";
    private static final String ISSUER_PATH = "/oauth2/default";
    private static final Duration NEVER_RETRY = Duration.ofHours(1);

    private EmbeddedServer provider;
    private FlakyDiscoveryController discovery;
    private HttpClient httpClient;
    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME));
        discovery = provider.getApplicationContext().getBean(FlakyDiscoveryController.class);
        httpClient = provider.getApplicationContext().createBean(HttpClient.class, provider.getURL());
        executor = Executors.newSingleThreadExecutor();
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
        httpClient.close();
        provider.close();
    }

    @Test
    void failureIsRethrownWithinTheBackOffWithoutContactingTheProvider() {
        discovery.failures = 1;
        DefaultOpenIdProviderMetadataFetcher fetcher = fetcher(NEVER_RETRY, null);

        HttpClientException first = assertThrows(HttpClientException.class, fetcher::fetch);
        HttpClientException second = assertThrows(HttpClientException.class, fetcher::fetch);

        assertSame(first, second);
        assertEquals(1, discovery.invocations.get());
    }

    @Test
    void fetchIsRetriedAfterTheBackOffAndTheResultIsMemoized() {
        discovery.failures = 1;
        DefaultOpenIdProviderMetadataFetcher fetcher = fetcher(Duration.ZERO, null);

        assertThrows(HttpClientException.class, fetcher::fetch);
        DefaultOpenIdProviderMetadata metadata = fetcher.fetch();

        assertEquals(issuer(), metadata.getIssuer());
        assertEquals(issuer() + "/v1/keys", metadata.getJwksUri());
        assertEquals("okta", metadata.getName());
        assertSame(metadata, fetcher.fetch());
        assertEquals(2, discovery.invocations.get());
    }

    @Test
    void fromANonBlockingThreadTheFetchFailsFastAndRunsOnTheExecutor() throws Exception {
        DefaultOpenIdProviderMetadataFetcher fetcher = fetcher(NEVER_RETRY, executor);

        Object failure = onNonBlockingThread(fetcher);
        assertInstanceOf(IllegalStateException.class, failure);

        // the background fetch was queued before this task on the single threaded executor
        executor.submit(() -> { }).get(30, TimeUnit.SECONDS);
        assertEquals(1, discovery.invocations.get());

        Object metadata = onNonBlockingThread(fetcher);
        assertInstanceOf(DefaultOpenIdProviderMetadata.class, metadata);
        assertEquals(issuer(), ((DefaultOpenIdProviderMetadata) metadata).getIssuer());
        assertEquals(1, discovery.invocations.get());
    }

    @Test
    void fromANonBlockingThreadAFailureWithinTheBackOffIsRethrownWithoutSchedulingAnotherFetch() throws Exception {
        discovery.failures = 1;
        DefaultOpenIdProviderMetadataFetcher fetcher = fetcher(NEVER_RETRY, executor);

        assertInstanceOf(IllegalStateException.class, onNonBlockingThread(fetcher));
        executor.submit(() -> { }).get(30, TimeUnit.SECONDS);
        Object failure = onNonBlockingThread(fetcher);
        executor.submit(() -> { }).get(30, TimeUnit.SECONDS);

        assertInstanceOf(HttpClientException.class, failure);
        assertEquals(1, discovery.invocations.get());
    }

    private Object onNonBlockingThread(DefaultOpenIdProviderMetadataFetcher fetcher) throws InterruptedException {
        AtomicReference<Object> outcome = new AtomicReference<>();
        Thread thread = new NonBlockingThread(() -> {
            try {
                outcome.set(fetcher.fetch());
            } catch (RuntimeException e) {
                outcome.set(e);
            }
        });
        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(30));
        return outcome.get();
    }

    private DefaultOpenIdProviderMetadataFetcher fetcher(Duration backoff, ExecutorService blockingExecutor) {
        OpenIdClientConfiguration configuration = mock(OpenIdClientConfiguration.class);
        when(configuration.getName()).thenReturn("okta");
        when(configuration.getConfigurationPath()).thenReturn("/.well-known/openid-configuration");
        when(configuration.isValidateIssuer()).thenReturn(true);
        when(configuration.getIssuerIdentifier()).thenReturn(Optional.of(issuer()));
        try {
            when(configuration.getIssuer()).thenReturn(Optional.of(new URL(issuer())));
        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        }
        return new DefaultOpenIdProviderMetadataFetcher(configuration, httpClient, backoff, blockingExecutor);
    }

    private String issuer() {
        return provider.getURL() + ISSUER_PATH;
    }

    private static final class NonBlockingThread extends Thread implements NonBlocking {
        NonBlockingThread(Runnable runnable) {
            super(runnable);
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller(ISSUER_PATH)
    static class FlakyDiscoveryController {
        final AtomicInteger invocations = new AtomicInteger();
        volatile int failures;
        private final EmbeddedServer embeddedServer;

        FlakyDiscoveryController(EmbeddedServer embeddedServer) {
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        HttpResponse<Map<String, Object>> index() {
            if (invocations.incrementAndGet() <= failures) {
                return HttpResponse.status(HttpStatus.SERVICE_UNAVAILABLE);
            }
            String issuer = embeddedServer.getURL() + ISSUER_PATH;
            return HttpResponse.ok(Map.of(
                "issuer", issuer,
                "authorization_endpoint", issuer + "/v1/authorize",
                "token_endpoint", issuer + "/v1/token",
                "jwks_uri", issuer + "/v1/keys"));
        }
    }
}
