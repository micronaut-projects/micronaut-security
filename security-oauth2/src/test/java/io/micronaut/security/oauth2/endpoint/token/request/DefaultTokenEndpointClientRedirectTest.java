package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.DefaultHttpClientConfiguration;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The HTTP client used to talk to the token endpoint must not follow redirects. Otherwise a malicious
 * or compromised provider can make the application send the token request (with the client credentials)
 * to any address the application can reach and treat the response of that address as the token response.
 */
class DefaultTokenEndpointClientRedirectTest {

    private static final String INTERNAL_ACCESS_TOKEN = "internal-service-token-fixture-not-a-secret";
    private static final String PROVIDER_ACCESS_TOKEN = "provider-token-fixture-not-a-secret";

    private static Map<String, Object> clientConfig(EmbeddedServer provider, String specName) {
        Map<String, Object> config = new HashMap<>();
        config.put("spec.name", specName);
        config.put("micronaut.security.oauth2.clients.evil.client-id", "client-id-fixture");
        config.put("micronaut.security.oauth2.clients.evil.client-secret", "client-secret-fixture-not-a-secret");
        config.put("micronaut.security.oauth2.clients.evil.token.url", provider.getURL() + "/oauth/token");
        config.put("micronaut.security.oauth2.clients.evil.token.auth-method", AuthenticationMethod.CLIENT_SECRET_BASIC.toString());
        return config;
    }

    @Test
    void tokenEndpointClientDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "DefaultTokenEndpointClientRedirectTestProvider"))) {
            try (ApplicationContext ctx = ApplicationContext.run(clientConfig(provider, "DefaultTokenEndpointClientRedirectTest"))) {
                assertDoesNotFollowRedirects(provider, ctx, provider.getURL() + "/oauth/token", provider.getURL() + "/direct/token");
            }
        }
    }

    /**
     * An {@code HttpClient} bean named after the provider, which follows redirects, must not be used as is.
     */
    @Test
    void providerNamedHttpClientBeanDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "DefaultTokenEndpointClientRedirectTestProvider"))) {
            try (ApplicationContext ctx = ApplicationContext.run(clientConfig(provider, "DefaultTokenEndpointClientRedirectTestNamedClient"))) {
                assertTrue(ctx.containsBean(HttpClient.class, Qualifiers.byName("evil")));
                assertDoesNotFollowRedirects(provider, ctx, provider.getURL() + "/oauth/token", provider.getURL() + "/direct/token");
            }
        }
    }

    /**
     * A service configuration named after the provider contributes its settings (here, the service url which resolves
     * the relative token endpoint url) but its {@code follow-redirects} setting is ignored.
     */
    @Test
    void providerNamedServiceConfigurationDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "DefaultTokenEndpointClientRedirectTestProvider"))) {
            Map<String, Object> config = clientConfig(provider, "DefaultTokenEndpointClientRedirectTest");
            config.put("micronaut.http.services.evil.url", provider.getURL().toString());
            config.put("micronaut.http.services.evil.follow-redirects", "true");
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertDoesNotFollowRedirects(provider, ctx, "/oauth/token", "/direct/token");
            }
        }
    }

    private static void assertDoesNotFollowRedirects(EmbeddedServer provider, ApplicationContext ctx, String redirectingUrl, String directUrl) {
        RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);
        TokenEndpointClient tokenEndpointClient = ctx.getBean(TokenEndpointClient.class);
        OauthClientConfiguration clientConfiguration = ctx.getBean(OauthClientConfiguration.class, Qualifiers.byName("evil"));

        // rejected path: the token endpoint redirects to an internal address
        ClientCredentialsTokenRequestContext redirecting = new ClientCredentialsTokenRequestContext("read",
            new DefaultSecureEndpoint(redirectingUrl, Collections.singletonList(AuthenticationMethod.CLIENT_SECRET_BASIC)),
            clientConfiguration);
        TokenResponse response = sendRequest(tokenEndpointClient, redirecting);
        assertTrue(response == null || response.getAccessToken() == null,
            "A response obtained by following a redirect must not be treated as the token response");
        assertEquals(0, counter.internalRequests.get(), "The redirect target must not be requested");
        assertEquals(1, counter.redirectingRequests.get());

        // accepted path: a token endpoint which answers directly works
        ClientCredentialsTokenRequestContext direct = new ClientCredentialsTokenRequestContext("read",
            new DefaultSecureEndpoint(directUrl, Collections.singletonList(AuthenticationMethod.CLIENT_SECRET_BASIC)),
            clientConfiguration);
        TokenResponse directResponse = sendRequest(tokenEndpointClient, direct);
        assertNotNull(directResponse);
        assertEquals(PROVIDER_ACCESS_TOKEN, directResponse.getAccessToken());
        assertEquals(0, counter.internalRequests.get());
    }

    private static TokenResponse sendRequest(TokenEndpointClient client, ClientCredentialsTokenRequestContext context) {
        try {
            return Mono.from(client.sendRequest(context)).block();
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Requires(property = "spec.name", value = "DefaultTokenEndpointClientRedirectTestNamedClient")
    @Factory
    static class NamedClientFactory {
        @Bean(preDestroy = "close")
        @Singleton
        @Named("evil")
        HttpClient evilClient(BeanContext beanContext) {
            DefaultHttpClientConfiguration configuration = new DefaultHttpClientConfiguration();
            configuration.setFollowRedirects(true);
            return beanContext.createBean(HttpClient.class, LoadBalancer.empty(), configuration);
        }
    }

    @Requires(property = "spec.name", value = "DefaultTokenEndpointClientRedirectTestProvider")
    @Singleton
    static class RequestCounter {
        final AtomicInteger redirectingRequests = new AtomicInteger();
        final AtomicInteger internalRequests = new AtomicInteger();
    }

    @Requires(property = "spec.name", value = "DefaultTokenEndpointClientRedirectTestProvider")
    @Controller
    static class ProviderController {
        private final RequestCounter counter;
        private final EmbeddedServer embeddedServer;

        ProviderController(RequestCounter counter, EmbeddedServer embeddedServer) {
            this.counter = counter;
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/oauth/token")
        HttpResponse<?> redirectingToken() {
            counter.redirectingRequests.incrementAndGet();
            // 307 preserves the method and the body, so the client would repeat the POST at the redirect target
            return HttpResponse.status(HttpStatus.TEMPORARY_REDIRECT)
                .header(HttpHeaders.LOCATION, embeddedServer.getURL() + "/internal/token");
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/direct/token")
        Map<String, Object> directToken() {
            return tokenResponse(PROVIDER_ACCESS_TOKEN);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.ALL)
        @Post("/internal/token")
        Map<String, Object> internalToken() {
            counter.internalRequests.incrementAndGet();
            return tokenResponse(INTERNAL_ACCESS_TOKEN);
        }

        private static Map<String, Object> tokenResponse(String accessToken) {
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            return response;
        }
    }
}
