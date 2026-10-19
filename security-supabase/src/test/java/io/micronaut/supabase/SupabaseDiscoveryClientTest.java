package io.micronaut.supabase;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.discovery.DiscoveryClient;
import io.micronaut.discovery.ServiceInstance;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code supabase} client resolves to the project URL and sends requests below the Auth path
 * when only the project is configured, and that explicit {@code micronaut.http.services.supabase.*} settings win.
 */
class SupabaseDiscoveryClientTest {
    private static final String SPEC_NAME = "SupabaseDiscoveryClientTest";

    private static EmbeddedServer server;

    @BeforeAll
    static void startServer() {
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.enabled", false));
    }

    @AfterAll
    static void stopServer() {
        server.close();
    }

    @Test
    void projectIdResolvesToTheHostedAuthUrl() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.project-id", "abcdefghijklmnopqrst"))) {
            SupabaseDiscoveryClient discovery = context.getBean(SupabaseDiscoveryClient.class);

            List<ServiceInstance> instances = first(discovery.getInstances("supabase"));
            assertEquals(1, instances.size());
            assertEquals(URI.create("https://abcdefghijklmnopqrst.supabase.co"), instances.getFirst().getURI());
            assertEquals(List.of("supabase"), first(discovery.getServiceIds()));
        }
    }

    @Test
    void projectUrlResolvesWithoutTrailingSlash() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.url", "https://api.example.com/"))) {
            List<ServiceInstance> instances = first(context.getBean(SupabaseDiscoveryClient.class).getInstances("supabase"));

            assertEquals(URI.create("https://api.example.com"), instances.getFirst().getURI());
        }
    }

    @Test
    void otherServiceIdsAreNotResolved() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.project-id", "abcdefghijklmnopqrst"))) {
            assertTrue(first(context.getBean(SupabaseDiscoveryClient.class).getInstances("other")).isEmpty());
        }
    }

    @Test
    void discoveryClientIsAbsentWithoutProject() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.publishable-key", "sb_publishable_fixture"))) {
            assertFalse(context.containsBean(SupabaseDiscoveryClient.class));
        }
    }

    @Test
    void discoveryClientIsRegisteredWithTheCompositeDiscovery() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.project-id", "abcdefghijklmnopqrst"))) {
            List<ServiceInstance> instances = first(context.getBean(DiscoveryClient.class).getInstances("supabase"));

            assertEquals(URI.create("https://abcdefghijklmnopqrst.supabase.co"), instances.getFirst().getURI());
        }
    }

    @Test
    void clientReachesTheAuthApiBelowTheProjectUrl() {
        try (ApplicationContext context = clientContext(Map.of("supabase.url", server.getURL().toString()))) {
            assertEquals("auth", context.getBean(ProbeClient.class).health());
        }
    }

    @Test
    void clientTuningCombinesWithTheDiscoveredUrl() {
        try (ApplicationContext context = clientContext(Map.of(
            "supabase.url", server.getURL().toString(),
            "micronaut.http.services.supabase.follow-redirects", false))) {
            assertEquals("auth", context.getBean(ProbeClient.class).health());
        }
    }

    @Test
    void explicitServiceUrlTakesPrecedenceOverTheProjectUrl() {
        try (ApplicationContext context = clientContext(Map.of(
            "supabase.url", "http://127.0.0.1:1",
            "micronaut.http.services.supabase.url", server.getURL().toString()))) {
            assertEquals("auth", context.getBean(ProbeClient.class).health());
        }
    }

    @Test
    void emptyAuthPathAddressesTheServerRoot() {
        try (ApplicationContext context = clientContext(Map.of(
            "supabase.url", server.getURL().toString(),
            "supabase.auth-path", ""))) {
            assertEquals("root", context.getBean(ProbeClient.class).health());
        }
    }

    /**
     * Blocks for the single value of a publisher; Reactor is not on this module's test classpath.
     */
    private static <T> T first(Publisher<T> publisher) {
        CompletableFuture<T> future = new CompletableFuture<>();
        publisher.subscribe(new Subscriber<>() {
            @Override
            public void onSubscribe(Subscription subscription) {
                subscription.request(1);
            }

            @Override
            public void onNext(T value) {
                future.complete(value);
            }

            @Override
            public void onError(Throwable error) {
                future.completeExceptionally(error);
            }

            @Override
            public void onComplete() {
                future.complete(null);
            }
        });
        return future.join();
    }

    private static ApplicationContext clientContext(Map<String, Object> properties) {
        Map<String, Object> all = new java.util.HashMap<>(properties);
        all.put("spec.name", SPEC_NAME);
        return ApplicationContext.run(all);
    }

    /**
     * Declared like {@code SupabaseAuthClient}: same service id and the Auth path as context path.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Client(id = SupabaseApiKeyClientFilter.SERVICE_ID, path = "${" + SupabaseConfiguration.AUTH_PATH_PROPERTY + ":" + SupabaseConfiguration.AUTH_PATH + "}")
    interface ProbeClient {
        @Get("/health")
        String health();
    }

    /**
     * Answers {@code auth} below the Auth API path and {@code root} at the server root, to tell the two apart.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class ProbeController {
        @Get("/auth/v1/health")
        String authHealth() {
            return "auth";
        }

        @Get("/health")
        String rootHealth() {
            return "root";
        }
    }
}
