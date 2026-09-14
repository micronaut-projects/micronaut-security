package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.client.HttpClient;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultTokenEndpointClientCloseTest {

    private static final Map<String, Object> CONFIGURATION = Map.of("spec.name", "DefaultTokenEndpointClientCloseTest");

    @Test
    void destroyingTheBeanClosesTheDefaultClientItCreated() {
        try (ApplicationContext ctx = ApplicationContext.run(CONFIGURATION)) {
            DefaultTokenEndpointClient tokenEndpointClient = ctx.getBean(DefaultTokenEndpointClient.class);
            HttpClient defaultClient = tokenEndpointClient.getClient("foo");
            assertTrue(defaultClient.isRunning());

            ctx.destroyBean(DefaultTokenEndpointClient.class);

            assertFalse(defaultClient.isRunning());
        }
    }

    @Test
    void closeDoesNotCloseASuppliedClient() {
        try (ApplicationContext ctx = ApplicationContext.run(CONFIGURATION);
             HttpClient suppliedClient = ctx.createBean(HttpClient.class)) {
            DefaultTokenEndpointClient tokenEndpointClient = new DefaultTokenEndpointClient(suppliedClient);
            tokenEndpointClient.getClient("foo");

            tokenEndpointClient.close();

            assertTrue(suppliedClient.isRunning());
        }
    }
}
