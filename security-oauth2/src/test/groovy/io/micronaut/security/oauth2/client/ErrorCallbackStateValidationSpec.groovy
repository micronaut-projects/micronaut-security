package io.micronaut.security.oauth2.client

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.AppenderBase
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.http.uri.UriBuilder
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.event.LoginFailedEvent
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.authorization.state.validation.StateValidator
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import org.slf4j.LoggerFactory
import reactor.core.publisher.Flux
import spock.lang.Specification

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList

/**
 * RFC 6749 section 4.1.2.1 returns the {@code state} parameter on error responses so that clients can bind
 * them to a pending authorization request. An error callback must therefore go through state validation
 * before it is honoured as an error reported by the authorization server.
 */
class ErrorCallbackStateValidationSpec extends Specification {

    private static final String LOGIN_FAILURE = '/login/failed'

    void "OAuth 2.0 client: error callback is bound to a pending flow through the state"() {
        given: 'an authorization server and an application configured with a manual OAuth 2.0 client'
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'AuthServerErrorCallbackStateValidationSpec',
        ])
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'ErrorCallbackStateValidationSpec',
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.login-failure': LOGIN_FAILURE,
                'micronaut.http.client.follow-redirects': false,
                'micronaut.security.oauth2.clients.auth.authorization.url': "http://localhost:${authServer.port}/oauth2/default/v1/authorize".toString(),
                'micronaut.security.oauth2.clients.auth.token.url': "http://localhost:${authServer.port}/oauth2/default/v1/token".toString(),
                'micronaut.security.oauth2.clients.auth.client-id': 'xxx',
                'micronaut.security.oauth2.clients.auth.client-secret': 'yyy',
        ])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        HttpClient authServerHttpClient = authServer.applicationContext.createBean(HttpClient, authServer.URL)
        BlockingHttpClient authServerClient = authServerHttpClient.toBlocking()
        AuthServerController authServerController = authServer.applicationContext.getBean(AuthServerController)
        LoginFailedEventListener loginFailedEvents = server.applicationContext.getBean(LoginFailedEventListener)
        MemoryAppender appender = attachAppender()

        expect:
        server.applicationContext.containsBean(StateValidator)
        server.applicationContext.getBean(OauthClient) instanceof DefaultOauthClient

        when: 'an error callback arrives without any pending authorization flow'
        String description = 'attacker' + UUID.randomUUID().toString().replaceAll('-', '')
        HttpResponse<?> response = client.exchange(errorCallback(description))

        then: 'the callback is handled as a failed login (invalid state), not as a provider error'
        HttpStatus.SEE_OTHER == response.status()
        LOGIN_FAILURE == response.header(HttpHeaders.LOCATION)
        loginFailedEvents.messages().any { it.startsWith('State validation failed') }

        and: 'the attacker controlled description is not logged'
        !appender.logged(description, Level.INFO)
        !appender.logged(description, Level.TRACE)

        when: 'an error callback arrives with a state that does not match any persisted state'
        loginFailedEvents.events.clear()
        response = client.exchange(errorCallback(description, 'eyJub25jZSI6ImZvcmdlZCJ9'))

        then:
        HttpStatus.SEE_OTHER == response.status()
        LOGIN_FAILURE == response.header(HttpHeaders.LOCATION)
        loginFailedEvents.messages().any { it.startsWith('State validation failed') }

        when: 'a real authorization flow is started'
        loginFailedEvents.events.clear()
        response = client.exchange(HttpRequest.GET('/oauth/login/auth'))

        then:
        HttpStatus.FOUND == response.status()

        when:
        Cookie stateCookie = response.cookies.get('OAUTH2_STATE')
        authServerClient.exchange(HttpRequest.GET(response.header(HttpHeaders.LOCATION)))

        then:
        stateCookie
        authServerController.state

        when: 'the authorization server answers that flow with an error response carrying the correct state'
        client.exchange(errorCallback(description, authServerController.state).cookie(stateCookie))

        then: 'the existing provider error handling is kept (bad request for non HTML requests)'
        HttpClientResponseException e = thrown()
        HttpStatus.BAD_REQUEST == e.status
        loginFailedEvents.events.isEmpty()

        when: 'the same legitimate error callback is sent by a browser'
        response = client.exchange(errorCallback(description, authServerController.state)
                .cookie(stateCookie)
                .accept(MediaType.TEXT_HTML))

        then: 'the existing provider error handling redirects to the login failure page'
        HttpStatus.SEE_OTHER == response.status()
        LOGIN_FAILURE == response.header(HttpHeaders.LOCATION)

        cleanup:
        detachAppender(appender)
        client.close()
        httpClient.close()
        authServerClient.close()
        authServerHttpClient.close()
        server.close()
        authServer.close()
    }

    void "OpenID Connect client: error callback is bound to a pending flow through the state"() {
        given: 'an authorization server and an application configured with an OpenID Connect client'
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'AuthServerErrorCallbackStateValidationSpec',
        ])
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'ErrorCallbackStateValidationSpec',
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.login-failure': LOGIN_FAILURE,
                'micronaut.http.client.follow-redirects': false,
                'micronaut.security.oauth2.clients.openid.openid.issuer': "http://localhost:${authServer.port}/oauth2/default".toString(),
                'micronaut.security.oauth2.clients.openid.client-id': 'xxx',
                'micronaut.security.oauth2.clients.openid.client-secret': 'yyy',
        ])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        HttpClient authServerHttpClient = authServer.applicationContext.createBean(HttpClient, authServer.URL)
        BlockingHttpClient authServerClient = authServerHttpClient.toBlocking()
        AuthServerController authServerController = authServer.applicationContext.getBean(AuthServerController)
        LoginFailedEventListener loginFailedEvents = server.applicationContext.getBean(LoginFailedEventListener)
        MemoryAppender appender = attachAppender()

        expect:
        server.applicationContext.containsBean(StateValidator)
        server.applicationContext.getBean(OauthClient) instanceof DefaultOpenIdClient

        when: 'an error callback arrives without any pending authorization flow'
        String description = 'attacker' + UUID.randomUUID().toString().replaceAll('-', '')
        HttpResponse<?> response = client.exchange(errorCallback(description, null, 'openid'))

        then: 'the callback is handled as a failed login (invalid state), not as a provider error'
        HttpStatus.SEE_OTHER == response.status()
        LOGIN_FAILURE == response.header(HttpHeaders.LOCATION)
        loginFailedEvents.messages().any { it.startsWith('State validation failed') }

        and: 'the attacker controlled description is not logged'
        !appender.logged(description, Level.INFO)
        !appender.logged(description, Level.TRACE)

        when: 'a real authorization flow is started'
        loginFailedEvents.events.clear()
        response = client.exchange(HttpRequest.GET('/oauth/login/openid'))

        then:
        HttpStatus.FOUND == response.status()

        when:
        Cookie stateCookie = response.cookies.get('OAUTH2_STATE')
        authServerClient.exchange(HttpRequest.GET(response.header(HttpHeaders.LOCATION)))

        then:
        stateCookie
        authServerController.state

        when: 'the authorization server answers that flow with an error response carrying the correct state'
        client.exchange(errorCallback(description, authServerController.state, 'openid').cookie(stateCookie))

        then: 'the existing provider error handling is kept (bad request for non HTML requests)'
        HttpClientResponseException e = thrown()
        HttpStatus.BAD_REQUEST == e.status
        loginFailedEvents.events.isEmpty()

        cleanup:
        detachAppender(appender)
        client.close()
        httpClient.close()
        authServerClient.close()
        authServerHttpClient.close()
        server.close()
        authServer.close()
    }

    void "without a StateValidator bean an error callback keeps the existing provider error handling"() {
        given: 'an application whose state persistence is unavailable, so no StateValidator bean exists'
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name': 'ErrorCallbackStateValidationSpec',
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.login-failure': LOGIN_FAILURE,
                'micronaut.http.client.follow-redirects': false,
                'micronaut.security.oauth2.state.persistence': 'none',
                'micronaut.security.oauth2.clients.auth.authorization.url': 'http://localhost:1/oauth2/default/v1/authorize',
                'micronaut.security.oauth2.clients.auth.token.url': 'http://localhost:1/oauth2/default/v1/token',
                'micronaut.security.oauth2.clients.auth.client-id': 'xxx',
                'micronaut.security.oauth2.clients.auth.client-secret': 'yyy',
        ])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        LoginFailedEventListener loginFailedEvents = server.applicationContext.getBean(LoginFailedEventListener)

        expect:
        !server.applicationContext.containsBean(StateValidator)

        when:
        client.exchange(errorCallback('denied'))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.BAD_REQUEST == e.status
        loginFailedEvents.events.isEmpty()

        cleanup:
        client.close()
        httpClient.close()
        server.close()
    }

    private static HttpRequest<?> errorCallback(String description, String state = null, String provider = 'auth') {
        UriBuilder uriBuilder = UriBuilder.of('/oauth/callback').path(provider)
                .queryParam('error', 'access_denied')
                .queryParam('error_description', description)
        if (state != null) {
            uriBuilder.queryParam('state', state)
        }
        HttpRequest.GET(uriBuilder.build())
    }

    private static MemoryAppender attachAppender() {
        MemoryAppender appender = new MemoryAppender()
        Logger logger = (Logger) LoggerFactory.getLogger('io.micronaut.security')
        logger.setLevel(Level.TRACE)
        logger.addAppender(appender)
        appender.start()
        appender
    }

    private static void detachAppender(MemoryAppender appender) {
        Logger logger = (Logger) LoggerFactory.getLogger('io.micronaut.security')
        logger.detachAppender(appender)
        appender.stop()
    }

    static class MemoryAppender extends AppenderBase<ILoggingEvent> {
        final Collection<ILoggingEvent> events = new ConcurrentLinkedQueue<>()

        @Override
        protected void append(ILoggingEvent e) {
            events.add(e)
        }

        boolean logged(String text, Level minimumLevel) {
            events.any { it.level.isGreaterOrEqual(minimumLevel) && it.formattedMessage?.contains(text) }
        }
    }

    @Requires(property = 'spec.name', value = 'ErrorCallbackStateValidationSpec')
    @Singleton
    static class LoginFailedEventListener implements ApplicationEventListener<LoginFailedEvent> {
        final List<LoginFailedEvent> events = new CopyOnWriteArrayList<>()

        @Override
        void onApplicationEvent(LoginFailedEvent event) {
            events.add(event)
        }

        List<String> messages() {
            events.collect { (it.source as AuthenticationResponse).message.orElse('') }
        }
    }

    @Requires(property = 'spec.name', value = 'ErrorCallbackStateValidationSpec')
    @Requires(property = 'micronaut.security.oauth2.clients.auth.client-id')
    @Singleton
    @Named('auth')
    static class MockOauthAuthenticationMapper implements OauthAuthenticationMapper {
        @Override
        Publisher<AuthenticationResponse> createAuthenticationResponse(TokenResponse tokenResponse, @Nullable State state) {
            Flux.just(AuthenticationResponse.success('john'))
        }
    }

    @Requires(property = 'spec.name', value = 'ErrorCallbackStateValidationSpec')
    @Controller('/login')
    static class LoginFailedController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get('/failed')
        @Status(HttpStatus.OK)
        void failed() {
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerErrorCallbackStateValidationSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        String state

        AuthServerController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver
        }

        @Get('/oauth2/default/v1/authorize')
        @Status(HttpStatus.OK)
        void authorize(HttpRequest<?> request) {
            state = request.getParameters().get('state')
        }

        @Get('/oauth2/default/.well-known/openid-configuration')
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default",' +
                    '"authorization_endpoint":"' + host + '/oauth2/default/v1/authorize",' +
                    '"token_endpoint":"' + host + '/oauth2/default/v1/token",' +
                    '"jwks_uri":"' + host + '/oauth2/default/v1/keys",' +
                    '"response_types_supported":["code"],' +
                    '"subject_types_supported":["public"],' +
                    '"id_token_signing_alg_values_supported":["RS256"]}'
        }
    }
}
