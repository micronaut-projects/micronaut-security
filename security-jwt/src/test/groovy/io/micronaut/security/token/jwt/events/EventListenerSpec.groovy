package io.micronaut.security.token.jwt.events

import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.event.AccessTokenGeneratedEvent
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import jakarta.inject.Singleton

class EventListenerSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        "EventListenerSpec"
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
                'micronaut.security.authentication': 'bearer',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    def "successful login publishes AccessTokenGeneratedEvent and RefreshTokenGeneratedEvent if JWT authentication enabled"() {
        when:
        HttpRequest request = HttpRequest.POST("/login", new UsernamePasswordCredentials("user", "password"))
        client.exchange(request)

        then:
        embeddedServer.applicationContext.getBean(AccessTokenGeneratedEventListener).events.size() ==
                old(embeddedServer.applicationContext.getBean(AccessTokenGeneratedEventListener).events.size()) + 1
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class RefreshTokenGeneratedEventListener implements ApplicationEventListener<RefreshTokenGeneratedEvent> {
        List<RefreshTokenGeneratedEvent> events = []
        @Override
        void onApplicationEvent(RefreshTokenGeneratedEvent event) {
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class AccessTokenGeneratedEventListener implements ApplicationEventListener<AccessTokenGeneratedEvent> {
        List<AccessTokenGeneratedEvent> events = []
        @Override
        void onApplicationEvent(AccessTokenGeneratedEvent event) {
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "EventListenerSpec")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }

}
