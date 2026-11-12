package io.micronaut.security.oauth2.client.clientcredentials;

import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.ClientCredentialsGrant;
import io.micronaut.security.oauth2.grants.GrantType;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ClientCredentialsClientTest {

    @Test
    void ofCreatesClientThatUsesProvidedHttpClient() {
        HttpClient httpClient = mock(HttpClient.class);
        TokenResponse tokenResponse = new TokenResponse("access-token", "Bearer");
        tokenResponse.setExpiresIn(3600);
        stubTokenResponse(httpClient, tokenResponse);
        OauthClientConfiguration configuration = OauthClientConfiguration.builder()
                .name("auth-server")
                .clientId("client-id")
                .clientSecret("client-secret")
                .token("https://auth.example.com/token", AuthenticationMethods.CLIENT_SECRET_BASIC)
                .clientCredentials()
                .build();

        ClientCredentialsClient client = ClientCredentialsClient.of(httpClient, configuration);
        TokenResponse response = Mono.from(client.requestToken("read")).block();

        assertInstanceOf(DefaultClientCredentialsClient.class, client);
        assertSame(tokenResponse, response);
        ArgumentCaptor<HttpRequest<Map<String, String>>> requestCaptor = httpRequestCaptor();
        verify(httpClient).retrieve(
                requestCaptor.capture(),
                eq(Argument.of(TokenResponse.class)),
                eq(Argument.of(TokenErrorResponse.class))
        );
        HttpRequest<Map<String, String>> request = requestCaptor.getValue();
        assertEquals(HttpMethod.POST, request.getMethod());
        assertEquals(URI.create("https://auth.example.com/token"), request.getUri());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED_TYPE, request.getContentType().orElseThrow());
        assertEquals(List.of(MediaType.APPLICATION_JSON_TYPE), request.getHeaders().accept());
        assertEquals(expectedBasicAuthHeader(), request.getHeaders().get(HttpHeaders.AUTHORIZATION));
        assertEquals(Map.of(
                "grant_type", GrantType.CLIENT_CREDENTIALS.toString(),
                ClientCredentialsGrant.KEY_SCOPES, "read"
        ), request.getBody().orElseThrow());
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void stubTokenResponse(HttpClient httpClient, TokenResponse tokenResponse) {
        doReturn(Flux.just(tokenResponse))
                .when(httpClient)
                .retrieve(any(HttpRequest.class), any(Argument.class), any(Argument.class));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static ArgumentCaptor<HttpRequest<Map<String, String>>> httpRequestCaptor() {
        return ArgumentCaptor.forClass((Class) HttpRequest.class);
    }

    private static String expectedBasicAuthHeader() {
        return "Basic " + Base64.getEncoder()
                .encodeToString("client-id:client-secret".getBytes(StandardCharsets.UTF_8));
    }
}
