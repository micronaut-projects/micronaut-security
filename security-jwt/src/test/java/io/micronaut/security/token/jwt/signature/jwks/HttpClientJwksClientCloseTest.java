package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.client.HttpClient;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpClientJwksClientCloseTest {

    @Test
    void destroyingTheBeanClosesTheClientsItCreatedButNotTheRegistryClients() {
        Map<String, Object> configuration = Map.of(
            "spec.name", "HttpClientJwksClientCloseTest",
            "micronaut.http.services.foo.url", "http://localhost:8080");
        try (ApplicationContext ctx = ApplicationContext.run(configuration)) {
            HttpClientJwksClient jwksClient = ctx.getBean(HttpClientJwksClient.class);
            HttpClient defaultClient = jwksClient.getClient(null);
            HttpClient unknownProviderClient = jwksClient.getClient("bar");
            HttpClient registryClient = jwksClient.getClient("foo");
            assertSame(defaultClient, unknownProviderClient);
            assertNotSame(defaultClient, registryClient);
            assertTrue(defaultClient.isRunning());
            assertTrue(registryClient.isRunning());

            // destroying the bean while the context is still running proves the @PreDestroy hook closes
            // the client, rather than the shared event loop group being shut down with the context.
            ctx.destroyBean(HttpClientJwksClient.class);

            assertFalse(defaultClient.isRunning());
            assertTrue(registryClient.isRunning());
        }
    }
}
