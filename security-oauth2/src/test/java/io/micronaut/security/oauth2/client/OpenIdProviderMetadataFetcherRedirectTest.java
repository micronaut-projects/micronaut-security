package io.micronaut.security.oauth2.client;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The HTTP client used to fetch the OpenID provider metadata must not follow redirects. Otherwise a malicious
 * or compromised issuer can make the application fetch any address it can reach and treat the JSON found there
 * as the provider metadata.
 */
class OpenIdProviderMetadataFetcherRedirectTest {

    @Test
    void openIdProviderMetadataFetcherDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "OpenIdProviderMetadataFetcherRedirectTestProvider"))) {
            RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);
            Map<String, Object> config = new HashMap<>();
            config.put("spec.name", "OpenIdProviderMetadataFetcherRedirectTest");
            config.put("micronaut.security.oauth2.clients.evil.client-id", "client-id-fixture");
            config.put("micronaut.security.oauth2.clients.evil.client-secret", "client-secret-fixture-not-a-secret");
            config.put("micronaut.security.oauth2.clients.evil.openid.issuer", provider.getURL().toString());
            config.put("micronaut.security.oauth2.clients.good.client-id", "client-id-fixture");
            config.put("micronaut.security.oauth2.clients.good.client-secret", "client-secret-fixture-not-a-secret");
            config.put("micronaut.security.oauth2.clients.good.openid.issuer", provider.getURL() + "/direct");
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                // rejected path: the discovery document redirects to an internal address
                OpenIdProviderMetadataFetcher evil = ctx.getBean(OpenIdProviderMetadataFetcher.class, Qualifiers.byName("evil"));
                assertThrows(DisabledBeanException.class, evil::fetch);
                assertEquals(0, counter.internalRequests.get(), "The redirect target must not be requested");

                // accepted path: a discovery document served directly is used
                OpenIdProviderMetadataFetcher good = ctx.getBean(OpenIdProviderMetadataFetcher.class, Qualifiers.byName("good"));
                assertEquals(provider.getURL() + "/direct/oauth/token", good.fetch().getTokenEndpoint());
                assertEquals(0, counter.internalRequests.get());
            }
        }
    }

    @Requires(property = "spec.name", value = "OpenIdProviderMetadataFetcherRedirectTestProvider")
    @Singleton
    static class RequestCounter {
        final AtomicInteger internalRequests = new AtomicInteger();
    }

    @Requires(property = "spec.name", value = "OpenIdProviderMetadataFetcherRedirectTestProvider")
    @Controller
    static class ProviderController {
        private final RequestCounter counter;
        private final EmbeddedServer embeddedServer;

        ProviderController(RequestCounter counter, EmbeddedServer embeddedServer) {
            this.counter = counter;
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        HttpResponse<?> redirectingConfiguration() {
            return HttpResponse.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, embeddedServer.getURL() + "/internal/openid-configuration");
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/internal/openid-configuration")
        Map<String, Object> internalConfiguration() {
            counter.internalRequests.incrementAndGet();
            return metadata(embeddedServer.getURL() + "/internal");
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/direct/.well-known/openid-configuration")
        Map<String, Object> directConfiguration() {
            return metadata(embeddedServer.getURL() + "/direct");
        }

        private static Map<String, Object> metadata(String baseUrl) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("issuer", baseUrl);
            metadata.put("authorization_endpoint", baseUrl + "/oauth/authorize");
            metadata.put("token_endpoint", baseUrl + "/oauth/token");
            metadata.put("jwks_uri", baseUrl + "/jwks");
            return metadata;
        }
    }
}
