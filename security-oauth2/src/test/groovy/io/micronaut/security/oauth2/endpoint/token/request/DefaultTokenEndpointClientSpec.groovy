package io.micronaut.security.oauth2.endpoint.token.request

import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import reactor.core.publisher.Mono
import spock.lang.Specification

import java.nio.charset.StandardCharsets

class DefaultTokenEndpointClientSpec extends Specification {

    private static final String TOKEN_URL = 'http://localhost/oauth/token'

    private HttpRequest<?> sentRequest

    private DefaultTokenEndpointClient tokenEndpointClient

    void setup() {
        HttpClient httpClient = Stub(HttpClient) {
            retrieve(_, _, _) >> { args ->
                sentRequest = args[0] as HttpRequest
                Mono.just(new TokenResponse())
            }
        }
        tokenEndpointClient = new DefaultTokenEndpointClient(httpClient)
    }

    void "client_secret_basic form-url-encodes client_id and client_secret before Base64 encoding"() {
        when:
        send('my:client', 's%cret ñ', AuthenticationMethods.CLIENT_SECRET_BASIC)

        then:
        decodedBasicCredentials() == 'my%3Aclient:s%25cret+%C3%B1'
        sentRequest.body.get()['client_id'] == null
        sentRequest.body.get()['client_secret'] == null
    }

    void "client_secret_basic with a #description client secret sends no Authorization header and client_id in the body"() {
        when:
        send('my-client', secret, AuthenticationMethods.CLIENT_SECRET_BASIC)

        then:
        !sentRequest.headers.contains(HttpHeaders.AUTHORIZATION)
        sentRequest.body.get()['client_id'] == 'my-client'
        !sentRequest.body.get().containsKey('client_secret')

        where:
        description | secret
        'null'      | null
        'empty'     | ''
        'blank'     | '   '
    }

    void "client_secret_basic without a client secret falls through to none even when client_secret_post is also supported"() {
        when:
        send('my-client', null, AuthenticationMethods.CLIENT_SECRET_BASIC, AuthenticationMethods.CLIENT_SECRET_POST)

        then:
        !sentRequest.headers.contains(HttpHeaders.AUTHORIZATION)
        sentRequest.body.get()['client_id'] == 'my-client'
        !sentRequest.body.get().containsKey('client_secret')
    }

    void "client_secret_post sends client_id and client_secret in the body without encoding them"() {
        when:
        send('my:client', 's%cret ñ', AuthenticationMethods.CLIENT_SECRET_POST)

        then:
        !sentRequest.headers.contains(HttpHeaders.AUTHORIZATION)
        sentRequest.body.get()['client_id'] == 'my:client'
        sentRequest.body.get()['client_secret'] == 's%cret ñ'
    }

    void "none sends only the client_id in the body"() {
        when:
        send('my-client', 'secret', AuthenticationMethods.NONE)

        then:
        !sentRequest.headers.contains(HttpHeaders.AUTHORIZATION)
        sentRequest.body.get()['client_id'] == 'my-client'
        !sentRequest.body.get().containsKey('client_secret')
    }

    private void send(String clientId, String clientSecret, String... authMethods) {
        OauthClientConfiguration clientConfiguration = Stub(OauthClientConfiguration) {
            getName() >> 'authserver'
            getClientId() >> clientId
            getClientSecret() >> clientSecret
            getClientCredentials() >> Optional.empty()
        }
        DefaultSecureEndpoint endpoint = new DefaultSecureEndpoint(TOKEN_URL, authMethods as Set<String>)
        ClientCredentialsTokenRequestContext context = new ClientCredentialsTokenRequestContext(null, endpoint, clientConfiguration)
        Mono.from(tokenEndpointClient.sendRequest(context)).block()
        assert sentRequest != null
    }

    private String decodedBasicCredentials() {
        String authorization = sentRequest.headers.get(HttpHeaders.AUTHORIZATION)
        assert authorization?.startsWith('Basic ')
        new String(Base64.decoder.decode(authorization.substring('Basic '.length())), StandardCharsets.UTF_8)
    }
}
