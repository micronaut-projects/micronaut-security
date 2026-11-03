package io.micronaut.security.oauth2.endpoint.authorization.response

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.core.util.CollectionUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.event.LoginFailedEvent
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.nio.charset.StandardCharsets

/**
 * An OAuth 2.0 (manual endpoints) callback that passes state validation but carries no {@code code} parameter must
 * end in an authentication failure, not in a server error.
 */
class OauthCallbackMissingCodeSpec extends Specification {

    private static final String SPEC_NAME = 'OauthCallbackMissingCodeSpec'
    private static final String CODE_MISSING_MESSAGE = 'Authorization code missing from callback'

    void "oauth callback with a valid state and no code fails authentication (redirect enabled: #redirectEnabled)"() {
        given: 'a server with an OAuth 2.0 client using manual endpoints whose token endpoint is hosted by the server itself'
        int port = SocketUtils.findAvailableTcpPort()
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                               : SPEC_NAME,
                'micronaut.server.port'                                   : port,
                'micronaut.security.authentication'                       : 'cookie',
                'micronaut.security.redirect.enabled'                     : redirectEnabled,
                'micronaut.security.redirect.login-failure'               : '/login-failed',
                'micronaut.http.client.followRedirects'                   : false,
                'micronaut.security.oauth2.clients.auth.authorization.url': 'https://example.com/authorize',
                'micronaut.security.oauth2.clients.auth.token.url'        : "http://localhost:${port}/token".toString(),
                'micronaut.security.oauth2.clients.auth.client-id'        : 'xxx',
                'micronaut.security.oauth2.clients.auth.client-secret'    : 'xxx',
        ] as Map<String, Object>)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        TokenController tokenController = server.applicationContext.getBean(TokenController)
        LoginFailedEventListener loginFailedEventListener = server.applicationContext.getBean(LoginFailedEventListener)

        when: 'starting the authorization code flow'
        HttpResponse<?> response = client.exchange(HttpRequest.GET('/oauth/login/auth'))

        then: 'the user is redirected to the authorization endpoint with a state which is also persisted in a cookie'
        HttpStatus.FOUND == response.status()
        Cookie cookieState = response.cookies.get('OAUTH2_STATE')
        cookieState
        String state = stateFromLocation(response.header(HttpHeaders.LOCATION))
        state

        when: 'the callback arrives with the valid state but without an authorization code'
        HttpRequest<?> callbackRequest = HttpRequest.POST('/oauth/callback/auth', CollectionUtils.mapOf('state', state))
                .cookie(cookieState)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        HttpStatus status = exchangeStatus(client, callbackRequest)

        then: 'the login failed path of the login handler runs instead of a server error'
        failureStatus == status
        new PollingConditions().eventually {
            loginFailedEventListener.events.size() == 1
        }
        loginFailedEventListener.events[0].source instanceof AuthenticationResponse
        CODE_MISSING_MESSAGE == ((AuthenticationResponse) loginFailedEventListener.events[0].source).message.get()

        and: 'the token endpoint is never contacted'
        tokenController.codes.isEmpty()

        when: 'the callback arrives with the valid state and an authorization code'
        callbackRequest = HttpRequest.POST('/oauth/callback/auth', CollectionUtils.mapOf('code', 'xxx', 'state', state))
                .cookie(cookieState)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        response = client.exchange(callbackRequest)

        then: 'the code is exchanged at the token endpoint and the login succeeds'
        successStatus == response.status()
        ['xxx'] == tokenController.codes
        1 == loginFailedEventListener.events.size()

        cleanup:
        httpClient.close()
        server.close()

        where:
        redirectEnabled | failureStatus           | successStatus
        true            | HttpStatus.SEE_OTHER    | HttpStatus.SEE_OTHER
        false           | HttpStatus.UNAUTHORIZED | HttpStatus.OK
    }

    void "oauth callback with a valid state and no code redirects to the login failure url"() {
        given:
        int port = SocketUtils.findAvailableTcpPort()
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                               : SPEC_NAME,
                'micronaut.server.port'                                   : port,
                'micronaut.security.authentication'                       : 'cookie',
                'micronaut.security.redirect.login-failure'               : '/login-failed',
                'micronaut.http.client.followRedirects'                   : false,
                'micronaut.security.oauth2.clients.auth.authorization.url': 'https://example.com/authorize',
                'micronaut.security.oauth2.clients.auth.token.url'        : "http://localhost:${port}/token".toString(),
                'micronaut.security.oauth2.clients.auth.client-id'        : 'xxx',
                'micronaut.security.oauth2.clients.auth.client-secret'    : 'xxx',
        ] as Map<String, Object>)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<?> response = client.exchange(HttpRequest.GET('/oauth/login/auth'))
        Cookie cookieState = response.cookies.get('OAUTH2_STATE')
        String state = stateFromLocation(response.header(HttpHeaders.LOCATION))
        HttpRequest<?> callbackRequest = HttpRequest.POST('/oauth/callback/auth', CollectionUtils.mapOf('state', state))
                .cookie(cookieState)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        response = client.exchange(callbackRequest)

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/login-failed' == response.header(HttpHeaders.LOCATION)

        cleanup:
        httpClient.close()
        server.close()
    }

    private static HttpStatus exchangeStatus(BlockingHttpClient client, HttpRequest<?> request) {
        try {
            return client.exchange(request).status()
        } catch (HttpClientResponseException e) {
            return e.status
        }
    }

    private static String stateFromLocation(String location) {
        String query = new URI(location).rawQuery
        String pair = query.split('&').find { it.startsWith('state=') }
        pair ? URLDecoder.decode(pair.substring('state='.length()), StandardCharsets.UTF_8) : null
    }

    @Requires(property = 'spec.name', value = 'OauthCallbackMissingCodeSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class TokenController {
        final List<String> codes = Collections.synchronizedList([])

        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post('/token')
        Map<String, Object> token(@Body AuthorizationCodeGrant codeGrant) {
            codes << codeGrant.code
            [access_token: 'access-token', token_type: 'Bearer']
        }
    }

    @Requires(property = 'spec.name', value = 'OauthCallbackMissingCodeSpec')
    @Singleton
    @Named('auth')
    static class AuthAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            Mono.just(AuthenticationResponse.success('user'))
        }
    }

    @Requires(property = 'spec.name', value = 'OauthCallbackMissingCodeSpec')
    @Singleton
    static class LoginFailedEventListener implements ApplicationEventListener<LoginFailedEvent> {
        final List<LoginFailedEvent> events = Collections.synchronizedList([])

        @Override
        void onApplicationEvent(LoginFailedEvent event) {
            events << event
        }
    }
}
