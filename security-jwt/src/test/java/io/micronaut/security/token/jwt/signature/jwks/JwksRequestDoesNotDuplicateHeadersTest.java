package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.filter.ClientFilterChain;
import io.micronaut.http.filter.HttpClientFilter;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.reactivestreams.Publisher;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JwksRequestDoesNotDuplicateHeadersTest {
    static Stream<Arguments> paramsProvider() {
        return Stream.of(
            arguments(CacheableJwkSetFetcher.class, "micronaut.caches.jwks.expire-after-write", "0s"),
            arguments(ReactorCacheJwkSetFetcher.class, "micronaut.security.token.jwt.signatures.jwks.google.cache-expiration", "0"));
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    void jwksRequestDoesNotDuplicateHeadersTest(Class fetcherClass, String configName, String configValue) {
        Map<String, Object> authServerConfig = Map.of("spec.name", "JwksRequestDoesNotDuplicateHeadersTestGoogle");
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, authServerConfig)) {
            Map<String, Object> serverConfig = Map.of("spec.name", "JwksRequestDoesNotDuplicateHeadersTest",
                "micronaut.http.client.read-timeout", "5m",
                "micronaut.security.token.jwt.signatures.jwks.google.url",
            "http://localhost:" + authServer.getPort() + "/oauth2/v3/certs",
                configName, configValue);
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, serverConfig)) {
                assertInstanceOf(fetcherClass, server.getApplicationContext().getBean(JwkSetFetcher.class));
                HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL());
                BlockingHttpClient client = httpClient.toBlocking();
                assertNotNull(client);
                String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
                int numberOfRequests = 5;
                for (int i = 0; i < numberOfRequests; i++) {
                    assertEquals("{\"message\":\"Hello World\"}", client.retrieve(HttpRequest.GET("/").bearerAuth(jwt)));
                }
                assertEquals(5, authServer.getApplicationContext().getBean(GoogleAuthController.class).headers.size());
            }
        }
    }

    @Requires(property = "spec.name", value = "JwksRequestDoesNotDuplicateHeadersTest")
    @Controller
    static class HomeController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        Map<String, String> index() {
            return Collections.singletonMap("message", "Hello World");
        }
    }

    @Requires(property = "spec.name", value = "JwksRequestDoesNotDuplicateHeadersTest")
    @Filter(patterns = "/oauth2/v3/certs")
    static class AddHeaderFilter implements HttpClientFilter {
        public Publisher<? extends HttpResponse<?>> doFilter(MutableHttpRequest<?> request, ClientFilterChain chain) {
            return chain.proceed(request.header("hdr", "a really long string ..."));
        }
    }

    @Requires(property = "spec.name", value = "JwksRequestDoesNotDuplicateHeadersTestGoogle")
    @Controller
    static class GoogleAuthController {
        List<String> headers = new ArrayList<>();
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/oauth2/v3/certs")
        String index(HttpRequest<?> request) {
            headers.addAll(request.getHeaders().getAll("hdr"));
            return """
                {
                  "keys": [
                    {
                      "kty": "RSA",
                      "e": "AQAB",
                      "use": "sig",
                      "kid": "fa072f75784642615087c7182c101341e18f7a3a",
                      "n": "pleuF0RyDsETygZn89RpGVFNMxG_hdYVnvbHadvM1tYxs9ghDq93NFxejt--1QlwpLQ3yuVY_CKldkAWgzPVl8-oUBe5xh9jzpLUTqcyrS1aFLuzAe13-OTadUE18wvhz9goQf80rg5IztD_gBePOOBE7eWHGqWLghuMb7cIYjgFxqNFyPn8bF_7k8pQAeHIPua_6_GHhw3ML4msp-aU7O1io3Z4P_Bir_6_C5J9UtWAcJ0Ez0YC5FxOMkh27joO5mUas8krGnFqIJTOgDYXQC1QTu-HOCRNvi6gFMqEkDTP5oBK2cDPDq5L0T8Q0UanSPR0BuOTHesCXnDAdxdyXw",
                      "alg": "RS256"
                    },
                    {
                      "n": "5D9Xb4z8eFr-3Zh3m5GnM_KVqc6rskPL7EMa6lSxNiMJ-PhXGORU-S-QgLmMvHu3vAMfvxz6ph3JZDpdGT68wj-vWqqBudaDYCbnbkjXm6UpcrFMpGAiOS6gACNxpz80JXaO2DPtl9jTN6WyJY9tLHdqRfesfOlwzB0lmVZ8shSDh8usN3vB1KfYuR6Vytly1phaWJr92yMICKUjtXT-0SlrtqDgX_U2Swl4QyZN6rrfuG3F6Fmw-m12Ve_kyoPUb02bbJCSFDnIZsMvRlSZem5nUrs86zDPTWfNcB0LUYG8OgMzOev7r04h_RY2F6K7c8nE2EobYTrH0kw2QIf8vQ",
                      "alg": "RS256",
                      "kid": "eec534fa5b8caca201ca8d0ff96b54c562210d1e",
                      "e": "AQAB",
                      "kty": "RSA",
                      "use": "sig"
                    }
                  ]
                }
                """;
        }
    }
}
