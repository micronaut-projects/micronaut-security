package io.micronaut.security.oauth2.client.clientcredentials.propagation;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientCredentialsHeaderTokenPropagatorTest {

    @Test
    void findTokenComparesThePrefixIgnoringCase() {
        ClientCredentialsHeaderTokenPropagator propagator = propagator("Bearer");

        assertEquals(Optional.of("XXX"), propagator.findToken(HttpRequest.GET("/").header("Authorization", "Bearer XXX")));
        assertEquals(Optional.of("XXX"), propagator.findToken(HttpRequest.GET("/").header("Authorization", "bearer XXX")));
        assertEquals(Optional.empty(), propagator.findToken(HttpRequest.GET("/").header("Authorization", "Basic XXX")));
        assertEquals(Optional.empty(), propagator.findToken(HttpRequest.GET("/")));
    }

    @Test
    void findTokenReadsWhatWriteTokenWrote() {
        for (String prefix : new String[] {"Bearer", "Bearer "}) {
            ClientCredentialsHeaderTokenPropagator propagator = propagator(prefix);
            MutableHttpRequest<?> request = HttpRequest.GET("/");

            propagator.writeToken(request, "XXX");

            assertEquals("Bearer XXX", request.getHeaders().get("Authorization"));
            assertEquals(Optional.of("XXX"), propagator.findToken(request));
        }
    }

    private static ClientCredentialsHeaderTokenPropagator propagator(String prefix) {
        OauthClientConfigurationProperties.ClientCredentialsConfigurationProperties.HeaderTokenPropagatorConfigurationProperties configuration =
            new OauthClientConfigurationProperties.ClientCredentialsConfigurationProperties.HeaderTokenPropagatorConfigurationProperties();
        configuration.setPrefix(prefix);
        return new ClientCredentialsHeaderTokenPropagator(configuration);
    }
}
