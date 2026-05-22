package io.micronaut.security.tests;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.test.support.TestPropertyProvider;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestSuiteSecurityServiceTest {

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {
        //"scoped-value", supported in a reactive chain using micrometer-reactor
        "thread-local"
    })
    void securityServiceInReactiveChain(String propagation) {
        Map<String, Object> properties = new HashMap<>();
        if (propagation != null) {
            properties.put("micronaut.propagation", propagation);
        }
        properties.putAll(MySQL.getProperties());
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties)) {
            HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURI());
            BlockingHttpClient client = httpClient.toBlocking();
            URI uri = UriBuilder.of("/foo").path("mono").build();
            String principal = assertDoesNotThrow(() ->
                client.retrieve(HttpRequest.GET(uri)
                    .accept(MediaType.TEXT_PLAIN)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer xxx")));
            assertEquals("sherlock", principal);
        }
    }
}
