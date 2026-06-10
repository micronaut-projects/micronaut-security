package io.micronaut.security.oauth2.client.clientcredentials;

import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.keycloak.docker.Keycloak;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Testcontainers(disabledWithoutDocker = true)
class ClientCredentialsClientOfTest {

    @AfterAll
    public static void cleanupSpec() {
        Keycloak.destroy();
    }

    @Test
    void itIsPossibleToCreateAClientCredentialsClientWithoutApplicationContext() throws Exception {
        String issuer = Keycloak.getIssuer();
        String clientId = Keycloak.CLIENT_ID;
        String clientSecret = Keycloak.getClientSecret();
        try (HttpClient httpClient = HttpClient.create(new URL(issuer))) {
            String tokenUrl = tokenUrl(httpClient, issuer);
            assertNotNull(tokenUrl);
//tag::clientcredentialsof[]
            ClientCredentialsClient clientCredentialsClient = ClientCredentialsClient.of(httpClient,
                OauthClientConfiguration.builder().name("test")
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .token(tokenUrl)
                    .build());
//end::clientcredentialsof[]
            // Request a token
            TokenResponse tokenResponse = Mono.from(clientCredentialsClient.requestToken()).block();
            assertNotNull(tokenResponse);
            assertNotNull(tokenResponse.getAccessToken());

            // Request a token again.
            TokenResponse newTokenResponse = Mono.from(clientCredentialsClient.requestToken()).block();
            assertNotNull(newTokenResponse);
            assertNotNull(newTokenResponse.getAccessToken());
            // Token is cached
            assertEquals(tokenResponse, newTokenResponse);
        }
    }

    private static @NonNull String tokenUrl(HttpClient httpClient, String issuer) {
        DefaultOpenIdProviderMetadata openIdProviderMetadata = httpClient.toBlocking().retrieve(
            HttpRequest.GET(issuer + "/.well-known/openid-configuration"),
            Argument.of(DefaultOpenIdProviderMetadata.class));
        return openIdProviderMetadata.getTokenEndpoint();
    }
}
