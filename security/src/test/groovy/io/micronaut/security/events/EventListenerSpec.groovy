package io.micronaut.security.events

import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.event.LoginFailedEvent
import io.micronaut.security.event.LoginSuccessfulEvent
import io.micronaut.security.event.LogoutEvent
import io.micronaut.security.event.TokenValidatedEvent
import io.micronaut.security.handlers.LoginHandler
import io.micronaut.security.handlers.LogoutHandler
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton
import spock.util.concurrent.PollingConditions

class EventListenerSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'EventListenerSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'endpoints.beans.enabled': true,
            'endpoints.beans.sensitive': true,
        ]
    }

    @Override
    Map<String, Object> getLoginModeCookie() {
        [:]
    }

    def "failed login publishes LoginFailedEvent"() {
        given:
        LoginFailedEventListener loginFailedEventListener = embeddedServer.applicationContext.getBean(LoginFailedEventListener)

        when: "sending request to login with bogus/password"
        HttpRequest request = HttpRequest.POST("/login", new UsernamePasswordCredentials("bogus", "password"))
        client.exchange(request)

        then:
        def e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
        new PollingConditions().eventually {
            loginFailedEventListener.events.size() == 1
            loginFailedEventListener.events.authenticationRequest.identity == ["bogus"]
            loginFailedEventListener.events.host*.get() == [embeddedServer.getURL().toString()]
            loginFailedEventListener.events.locale == [Locale.default]
        }
    }

    def "successful login publishes LoginSuccessfulEvent"() {
        given:
        LoginSuccessfulEventListener loginSuccessfulEventListener = embeddedServer.applicationContext.getBean(LoginSuccessfulEventListener)

        when:
        HttpRequest request = HttpRequest.POST("/login", new UsernamePasswordCredentials("user", "password"))
        client.exchange(request)

        then:
        new PollingConditions().eventually {
            loginSuccessfulEventListener.events.size() == 1
            loginSuccessfulEventListener.events.host*.get() == [embeddedServer.getURL().toString()]
            loginSuccessfulEventListener.events.locale == [Locale.default]
        }
    }

    def "invoking logout triggers LogoutEvent"() {
        given:
        LogoutEventListener logoutEventListener = embeddedServer.applicationContext.getBean(LogoutEventListener)

        when:
        HttpRequest request = HttpRequest.POST("/logout", "").basicAuth("user", "password")
        client.exchange(request)

        then:
        noExceptionThrown()
        new PollingConditions().eventually {
            logoutEventListener.events.size() == 1
            logoutEventListener.events.source.name == ['user']
            logoutEventListener.events.host*.get() == [embeddedServer.getURL().toString()]
            logoutEventListener.events.locale == [Locale.default]
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class LoginSuccessfulEventListener implements ApplicationEventListener<LoginSuccessfulEvent> {
        List<LoginSuccessfulEvent> events = []
        @Override
        void onApplicationEvent(LoginSuccessfulEvent event) {
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class LogoutEventListener implements ApplicationEventListener<LogoutEvent> {
        List<LogoutEvent> events = []

        @Override
        void onApplicationEvent(LogoutEvent event) {
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class LoginFailedEventListener implements ApplicationEventListener<LoginFailedEvent> {
        volatile List<LoginFailedEvent> events = []
        @Override
        void onApplicationEvent(LoginFailedEvent event) {
            println "received login failed event"
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class TokenValidatedEventListener implements ApplicationEventListener<TokenValidatedEvent> {
        List<TokenValidatedEvent> events = []
        @Override
        void onApplicationEvent(TokenValidatedEvent event) {
            println "received token validated event"
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class LogoutFailedEventListener implements ApplicationEventListener<LogoutEvent> {
        List<LogoutEvent> events = []
        @Override
        void onApplicationEvent(LogoutEvent event) {
            println "received logout event"
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class CustomLogoutHandler implements LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> {

        @Override
        MutableHttpResponse<?> logout(HttpRequest<?> request) {
            HttpResponse.ok()
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class CustomLoginHandler implements LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> {

        @Override
        MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request) {
            HttpResponse.ok()
        }

        @Override
        MutableHttpResponse<?> loginRefresh(Authentication authentication, String refreshToken, HttpRequest<?> request) {
            throw new UnsupportedOperationException()
        }

        @Override
        MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
            HttpResponse.unauthorized()
        }
    }
}
