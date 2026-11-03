package io.micronaut.security.oauth2.endpoint.authorization.response

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.core.util.CollectionUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.event.LoginFailedEvent
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Singleton
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import java.nio.charset.StandardCharsets

/**
 * An OpenID Connect callback that passes state validation but carries no {@code code} parameter must end in an
 * authentication failure, not in a server error. The OpenID provider is a mock server exposing the discovery document.
 */
class OpenIdCallbackMissingCodeSpec extends Specification {

    private static final String CODE_MISSING_MESSAGE = 'Authorization code missing from callback'

    void "openid callback with a valid state and no code fails authentication"() {
        given: 'a mock OpenID provider and a server configured against it through discovery'
        EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'AuthServerOpenIdCallbackMissingCodeSpec',
        ] as Map<String, Object>)
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                                           : 'OpenIdCallbackMissingCodeSpec',
                'micronaut.security.authentication'                   : 'cookie',
                'micronaut.security.redirect.login-failure'           : '/login-failed',
                'micronaut.http.client.followRedirects'               : false,
                'micronaut.security.oauth2.clients.auth.openid.issuer': "http://localhost:${oauthServer.port}/oauth2/default".toString(),
                'micronaut.security.oauth2.clients.auth.client-id'    : 'xxx',
                'micronaut.security.oauth2.clients.auth.client-secret': 'xxx',
        ] as Map<String, Object>)
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        AuthServerController authServerController = oauthServer.applicationContext.getBean(AuthServerController)
        LoginFailedEventListener loginFailedEventListener = server.applicationContext.getBean(LoginFailedEventListener)

        expect:
        server.applicationContext.containsBean(OpenIdClient)

        when: 'starting the authorization code flow'
        HttpResponse<?> response = client.exchange(HttpRequest.GET('/oauth/login/auth'))

        then: 'the user is redirected to the authorization endpoint with a state which is also persisted in a cookie'
        HttpStatus.FOUND == response.status()
        response.header(HttpHeaders.LOCATION).startsWith("http://localhost:${oauthServer.port}/oauth2/default/v1/authorize")
        Cookie cookieState = response.cookies.get('OAUTH2_STATE')
        cookieState
        Cookie cookieNonce = response.cookies.get('OPENID_NONCE')
        cookieNonce
        String state = stateFromLocation(response.header(HttpHeaders.LOCATION))
        state

        when: 'the callback arrives with the valid state but without an authorization code'
        HttpRequest<?> callbackRequest = HttpRequest.POST('/oauth/callback/auth', CollectionUtils.mapOf('state', state))
                .cookie(cookieState)
                .cookie(cookieNonce)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        response = client.exchange(callbackRequest)

        then: 'the login failed path of the login handler runs instead of a server error'
        HttpStatus.SEE_OTHER == response.status()
        '/login-failed' == response.header(HttpHeaders.LOCATION)
        new PollingConditions().eventually {
            loginFailedEventListener.events.size() == 1
        }
        loginFailedEventListener.events[0].source instanceof AuthenticationResponse
        CODE_MISSING_MESSAGE == ((AuthenticationResponse) loginFailedEventListener.events[0].source).message.get()

        and: 'the token endpoint is never contacted'
        authServerController.codes.isEmpty()

        when: 'the callback arrives with the valid state and an authorization code'
        callbackRequest = HttpRequest.POST('/oauth/callback/auth', CollectionUtils.mapOf('code', 'xxx', 'state', state))
                .cookie(cookieState)
                .cookie(cookieNonce)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        HttpStatus status = exchangeStatus(client, callbackRequest)

        then: 'the code is exchanged at the token endpoint; the mock returns an id token which cannot be validated so the login is rejected'
        HttpStatus.UNAUTHORIZED == status
        ['xxx'] == authServerController.codes
        1 == loginFailedEventListener.events.size()

        cleanup:
        httpClient.close()
        server.close()
        oauthServer.close()
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

    @Requires(property = 'spec.name', value = 'AuthServerOpenIdCallbackMissingCodeSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        final List<String> codes = Collections.synchronizedList([])

        AuthServerController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post('/oauth2/default/v1/token')
        Map<String, Object> token(@Body AuthorizationCodeGrant codeGrant) {
            codes << codeGrant.code
            [access_token: 'access-token', token_type: 'Bearer', id_token: 'not-a-jwt']
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get('/keys')
        String keys() {
            '{"keys":[]}'
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get('/oauth2/default/.well-known/openid-configuration')
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default",' +
                    '"authorization_endpoint":"' + host + '/oauth2/default/v1/authorize",' +
                    '"token_endpoint":"' + host + '/oauth2/default/v1/token",' +
                    '"jwks_uri":"' + host + '/keys",' +
                    '"response_types_supported":["code"],' +
                    '"subject_types_supported":["public"],' +
                    '"id_token_signing_alg_values_supported":["RS256"],' +
                    '"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]}'
        }
    }

    @Requires(property = 'spec.name', value = 'OpenIdCallbackMissingCodeSpec')
    @Singleton
    static class LoginFailedEventListener implements ApplicationEventListener<LoginFailedEvent> {
        final List<LoginFailedEvent> events = Collections.synchronizedList([])

        @Override
        void onApplicationEvent(LoginFailedEvent event) {
            events << event
        }
    }
}
