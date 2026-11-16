package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultTokenEndpointClientTest {

    private static final String TOKEN_URL = "http://localhost/oauth/token";
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final String BASIC_PREFIX = "Basic ";

    @Test
    void clientSecretBasicFormUrlEncodesClientIdAndClientSecretBeforeBase64Encoding() {
        HttpRequest<?> request = send("my:client", "s%cret ñ", Set.of(AuthenticationMethods.CLIENT_SECRET_BASIC));

        assertEquals("my%3Aclient:s%25cret+%C3%B1", decodedBasicCredentials(request));
        assertFalse(body(request).containsKey(CLIENT_ID));
        assertFalse(body(request).containsKey(CLIENT_SECRET));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "abc8Q~x.Y_z-1 | abc8Q%7Ex.Y_z-1",
        "a+b/c=        | a%2Bb%2Fc%3D",
        "p@ss!w*rd     | p%40ss%21w*rd",
        "plain-secret  | plain-secret"
    })
    void clientSecretBasicEncodesCharactersFoundInProviderIssuedSecrets(String secret, String encoded) {
        HttpRequest<?> request = send("my-client", secret, Set.of(AuthenticationMethods.CLIENT_SECRET_BASIC));

        assertEquals("my-client:" + encoded, decodedBasicCredentials(request));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "''    | my-client:",
        "' '   | my-client:+",
        "'   ' | my-client:+++"
    })
    void clientSecretBasicPreservesEmptyAndSpaceOnlyClientSecrets(String secret, String expected) {
        HttpRequest<?> request = send("my-client", secret, Set.of(AuthenticationMethods.CLIENT_SECRET_BASIC));

        assertEquals(expected, decodedBasicCredentials(request));
        assertFalse(body(request).containsKey(CLIENT_ID));
        assertFalse(body(request).containsKey(CLIENT_SECRET));
    }

    @Test
    void clientSecretBasicIsUsedWhenTheEndpointDoesNotDeclareAuthenticationMethods() {
        HttpRequest<?> request = send("my-client", "s~cret", null);

        assertEquals("my-client:s%7Ecret", decodedBasicCredentials(request));
        assertFalse(body(request).containsKey(CLIENT_ID));
        assertFalse(body(request).containsKey(CLIENT_SECRET));
    }

    @Test
    void noAuthenticationMethodsAndNullClientSecretSendsOnlyTheClientIdInTheBody() {
        HttpRequest<?> request = send("my-client", null, null);

        assertClientIdOnlyInBody(request);
    }

    @Test
    void clientSecretBasicWithNullClientSecretSendsNoAuthorizationHeaderAndClientIdInTheBody() {
        HttpRequest<?> request = send("my-client", null, Set.of(AuthenticationMethods.CLIENT_SECRET_BASIC));

        assertClientIdOnlyInBody(request);
    }

    @Test
    void clientSecretBasicWithNullClientSecretFallsThroughToNoneEvenWhenClientSecretPostIsSupported() {
        HttpRequest<?> request = send("my-client", null,
            Set.of(AuthenticationMethods.CLIENT_SECRET_BASIC, AuthenticationMethods.CLIENT_SECRET_POST));

        assertClientIdOnlyInBody(request);
    }

    @Test
    void clientSecretPostSendsClientIdAndClientSecretInTheBodyWithoutEncodingThem() {
        HttpRequest<?> request = send("my:client", "s%cret ñ", Set.of(AuthenticationMethods.CLIENT_SECRET_POST));

        assertFalse(request.getHeaders().contains(HttpHeaders.AUTHORIZATION));
        assertEquals("my:client", body(request).get(CLIENT_ID));
        assertEquals("s%cret ñ", body(request).get(CLIENT_SECRET));
    }

    @Test
    void clientSecretPostPreservesAnEmptyClientSecret() {
        HttpRequest<?> request = send("my-client", "", Set.of(AuthenticationMethods.CLIENT_SECRET_POST));

        assertFalse(request.getHeaders().contains(HttpHeaders.AUTHORIZATION));
        assertEquals("my-client", body(request).get(CLIENT_ID));
        assertTrue(body(request).containsKey(CLIENT_SECRET));
        assertEquals("", body(request).get(CLIENT_SECRET));
    }

    @Test
    void clientSecretPostWithNullClientSecretSendsOnlyTheClientIdInTheBody() {
        HttpRequest<?> request = send("my-client", null, Set.of(AuthenticationMethods.CLIENT_SECRET_POST));

        assertClientIdOnlyInBody(request);
    }

    @Test
    void noneSendsOnlyTheClientIdInTheBody() {
        HttpRequest<?> request = send("my-client", "secret", Set.of(AuthenticationMethods.NONE));

        assertClientIdOnlyInBody(request);
    }

    private static void assertClientIdOnlyInBody(HttpRequest<?> request) {
        assertFalse(request.getHeaders().contains(HttpHeaders.AUTHORIZATION));
        assertEquals("my-client", body(request).get(CLIENT_ID));
        assertFalse(body(request).containsKey(CLIENT_SECRET));
    }

    @SuppressWarnings("unchecked")
    private static HttpRequest<?> send(String clientId, String clientSecret, Set<String> authMethods) {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.retrieve(any(HttpRequest.class), any(Argument.class), any(Argument.class)))
            .thenReturn(Mono.just(new TokenResponse()));
        OauthClientConfiguration clientConfiguration = OauthClientConfiguration.builder()
            .name("authserver")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .build();
        ClientCredentialsTokenRequestContext context = new ClientCredentialsTokenRequestContext(
            null, new DefaultSecureEndpoint(TOKEN_URL, authMethods), clientConfiguration);

        Mono.from(new DefaultTokenEndpointClient(httpClient).sendRequest(context)).block();

        ArgumentCaptor<HttpRequest<?>> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).retrieve(captor.capture(), any(Argument.class), any(Argument.class));
        return captor.getValue();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> body(HttpRequest<?> request) {
        return (Map<String, String>) request.getBody().orElseThrow();
    }

    private static String decodedBasicCredentials(HttpRequest<?> request) {
        String authorization = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
        assertNotNull(authorization);
        assertTrue(authorization.startsWith(BASIC_PREFIX));
        return new String(Base64.getDecoder().decode(authorization.substring(BASIC_PREFIX.length())), StandardCharsets.UTF_8);
    }
}
