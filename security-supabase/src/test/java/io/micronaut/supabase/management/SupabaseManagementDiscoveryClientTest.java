package io.micronaut.supabase.management;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code supabase-management} client resolves to the Management API URL without any HTTP
 * client configuration, and that explicit {@code micronaut.http.services.supabase-management.*} settings win.
 */
class SupabaseManagementDiscoveryClientTest {
    private static final String SPEC_NAME = "SupabaseManagementDiscoveryClientTest";

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
    void serviceResolvesToTheHostedManagementApiByDefault() {
        try (ApplicationContext context = ApplicationContext.run()) {
            SupabaseManagementDiscoveryClient discovery = context.getBean(SupabaseManagementDiscoveryClient.class);

            List<ServiceInstance> instances = first(discovery.getInstances(SupabaseManagementConfiguration.SERVICE_ID));
            assertEquals(1, instances.size());
            assertEquals(URI.create("https://api.supabase.com"), instances.getFirst().getURI());
            assertEquals(List.of(SupabaseManagementConfiguration.SERVICE_ID), first(discovery.getServiceIds()));
            assertEquals("Supabase Management API", discovery.getDescription());
        }
    }

    @Test
    void serviceResolvesToTheConfiguredUrl() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.management.url", "https://management.example.com/"))) {
            List<ServiceInstance> instances = first(context.getBean(SupabaseManagementDiscoveryClient.class)
                .getInstances(SupabaseManagementConfiguration.SERVICE_ID));

            assertEquals(URI.create("https://management.example.com"), instances.getFirst().getURI());
        }
    }

    @Test
    void otherServiceIdsAreNotResolved() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertTrue(first(context.getBean(SupabaseManagementDiscoveryClient.class).getInstances("supabase")).isEmpty());
        }
    }

    @Test
    void discoveryClientIsRegisteredWithTheCompositeDiscovery() {
        try (ApplicationContext context = ApplicationContext.run()) {
            List<ServiceInstance> instances = first(context.getBean(DiscoveryClient.class).getInstances(SupabaseManagementConfiguration.SERVICE_ID));

            assertEquals(URI.create("https://api.supabase.com"), instances.getFirst().getURI());
        }
    }

    @Test
    void closingReleasesNothing() {
        try (ApplicationContext context = ApplicationContext.run()) {
            SupabaseManagementDiscoveryClient discovery = context.getBean(SupabaseManagementDiscoveryClient.class);
            discovery.close();

            assertEquals(1, first(discovery.getInstances(SupabaseManagementConfiguration.SERVICE_ID)).size());
        }
    }

    @Test
    void clientReachesTheConfiguredManagementApi() {
        try (ApplicationContext context = clientContext(Map.of("supabase.management.url", server.getURL().toString()))) {
            assertEquals("ok", context.getBean(ProbeClient.class).health());
        }
    }

    @Test
    void clientTuningCombinesWithTheDiscoveredUrl() {
        try (ApplicationContext context = clientContext(Map.of(
            "supabase.management.url", server.getURL().toString(),
            "micronaut.http.services.supabase-management.follow-redirects", false))) {
            assertEquals("ok", context.getBean(ProbeClient.class).health());
        }
    }

    @Test
    void explicitServiceUrlTakesPrecedenceOverTheConfiguredUrl() {
        try (ApplicationContext context = clientContext(Map.of(
            "supabase.management.url", "http://127.0.0.1:1",
            "micronaut.http.services.supabase-management.url", server.getURL().toString()))) {
            assertEquals("ok", context.getBean(ProbeClient.class).health());
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
        Map<String, Object> all = new HashMap<>(properties);
        all.put("spec.name", SPEC_NAME);
        return ApplicationContext.run(all);
    }

    /**
     * Declared like the Management API clients: same service id, path below {@code /v1}.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Client(id = SupabaseManagementConfiguration.SERVICE_ID, path = "/v1")
    interface ProbeClient {
        @Get("/health")
        String health();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/v1/health")
    static class HealthController {
        @Get
        String health() {
            return "ok";
        }
    }
}
