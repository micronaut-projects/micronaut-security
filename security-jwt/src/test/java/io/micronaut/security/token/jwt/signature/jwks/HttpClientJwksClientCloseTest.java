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
    void destroyingTheBeanClosesTheClientsItCreated() {
        Map<String, Object> configuration = Map.of(
            "spec.name", "HttpClientJwksClientCloseTest",
            "micronaut.http.services.foo.url", "http://localhost:8080");
        try (ApplicationContext ctx = ApplicationContext.run(configuration)) {
            HttpClientJwksClient jwksClient = ctx.getBean(HttpClientJwksClient.class);
            HttpClient defaultClient = jwksClient.getClient(null);
            HttpClient unknownProviderClient = jwksClient.getClient("bar");
            // since 5.5.2 the client of a named service is created by the bean (it never follows redirects), not obtained from the registry
            HttpClient serviceClient = jwksClient.getClient("foo");
            assertSame(defaultClient, unknownProviderClient);
            assertNotSame(defaultClient, serviceClient);
            assertTrue(defaultClient.isRunning());
            assertTrue(serviceClient.isRunning());

            // destroying the bean while the context is still running proves the @PreDestroy hook closes
            // the client, rather than the shared event loop group being shut down with the context.
            ctx.destroyBean(HttpClientJwksClient.class);

            assertFalse(defaultClient.isRunning());
            assertFalse(serviceClient.isRunning());
        }
    }
}
