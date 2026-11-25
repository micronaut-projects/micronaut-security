package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The protected resource metadata {@code resource} value and the {@code WWW-Authenticate} {@code resource_metadata} URL
 * are, by default, derived from the request {@code Host} / {@code X-Forwarded-*} headers, which an unauthenticated caller
 * controls. {@code micronaut.security.oauth2.base-url} pins the base explicitly.
 */
class ProtectedResourceMetadataBaseUrlTest {

    private static final String SPEC_NAME = "ProtectedResourceMetadataBaseUrlTest";
    private static final String ISSUER = "https://idcs-abcde.identity.oraclecloud.com";
    private static final String METADATA_PATH = "/.well-known/oauth-protected-resource";

    @Test
    void withoutBaseUrlTheResourceAndResourceMetadataUrlsReflectTheSpoofedHostHeaders() throws JSONException {
        Map<String, Object> configuration = Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.oauth2.clients.oci.openid.issuer", ISSUER);
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            // documents the default behaviour: the attacker-supplied host is reflected to an unauthenticated caller
            String json = assertDoesNotThrow(() -> client.retrieve(spoofed(HttpRequest.GET(METADATA_PATH))));
            JSONAssert.assertEquals(expectedMetadata("https://evil.example.com"), json, true);

            String pathJson = assertDoesNotThrow(() -> client.retrieve(spoofed(HttpRequest.GET(METADATA_PATH + "/resource1"))));
            JSONAssert.assertEquals(expectedMetadata("https://evil.example.com/resource1"), pathJson, true);

            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(spoofed(HttpRequest.GET("/foobar").accept(MediaType.TEXT_PLAIN))));
            assertEquals("Bearer resource_metadata=\"https://evil.example.com" + METADATA_PATH + "/foobar\"",
                ex.getResponse().getHeaders().get("WWW-Authenticate"));
        }
    }

    @Test
    void withBaseUrlTheResourceAndResourceMetadataUrlsUseTheConfiguredBase() throws JSONException {
        Map<String, Object> configuration = Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.oauth2.base-url", "https://app.example.com/",
            "micronaut.security.oauth2.clients.oci.openid.issuer", ISSUER);
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            String json = assertDoesNotThrow(() -> client.retrieve(spoofed(HttpRequest.GET(METADATA_PATH))));
            JSONAssert.assertEquals(expectedMetadata("https://app.example.com"), json, true);

            String pathJson = assertDoesNotThrow(() -> client.retrieve(spoofed(HttpRequest.GET(METADATA_PATH + "/resource1"))));
            JSONAssert.assertEquals(expectedMetadata("https://app.example.com/resource1"), pathJson, true);

            // and without any spoofed headers the configured base is used too, not the embedded server URL
            String plainJson = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET(METADATA_PATH)));
            JSONAssert.assertEquals(expectedMetadata("https://app.example.com"), plainJson, true);

            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
                () -> client.exchange(spoofed(HttpRequest.GET("/foobar").accept(MediaType.TEXT_PLAIN))));
            assertEquals("Bearer resource_metadata=\"https://app.example.com" + METADATA_PATH + "/foobar\"",
                ex.getResponse().getHeaders().get("WWW-Authenticate"));
        }
    }

    private static <T> MutableHttpRequest<T> spoofed(MutableHttpRequest<T> request) {
        return request
            .header("Host", "evil.example.com")
            .header("X-Forwarded-Host", "evil.example.com")
            .header("X-Forwarded-Proto", "https");
    }

    private static String expectedMetadata(String resource) {
        return String.format("""
              {
               "resource": "%s",
               "authorization_servers": ["%s"]
              }
            """, resource, ISSUER);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/foobar")
    static class FooBarController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "foobar";
        }
    }
}
