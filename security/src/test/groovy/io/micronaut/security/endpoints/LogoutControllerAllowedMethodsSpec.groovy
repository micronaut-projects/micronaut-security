package io.micronaut.security.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.handlers.LogoutHandler
import jakarta.inject.Singleton
import spock.lang.Specification

class LogoutControllerAllowedMethodsSpec extends Specification {

    Map<String, Object> getConfiguration() {
        Map<String, Object> m = [:]
        if (specName) {
            m['spec.name'] = specName
        }
        m
    }

    String getSpecName() {
        'LogoutControllerAllowedMethodsSpec'
    }

    void "LogoutController does not accept GET requests by default"() {
        given:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration, Environment.TEST)
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

        when:
        client.toBlocking().exchange(HttpRequest.GET("/logout").basicAuth("user", "password"))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.METHOD_NOT_ALLOWED

        cleanup:
        client.close()
        embeddedServer.close()
    }

    void "LogoutController can accept GET requests if micronaut.security.endpoints.logout.get-allowed=true"() {
        given:
        Map<String, Object> m = new HashMap<>()
        m.putAll(configuration)
        m.put('micronaut.security.endpoints.logout.get-allowed', true)

        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, m, Environment.TEST)
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

        when:
        client.toBlocking().exchange(HttpRequest.GET("/logout").basicAuth("user", "password"))

        then:
        noExceptionThrown()

        cleanup:
        client.close()
        embeddedServer.close()
    }

    void "test logging out without credentials"() {
        given:
        Map<String, Object> m = new HashMap<>()
        m.putAll(configuration)
        m.put('micronaut.security.endpoints.logout.get-allowed', true)

        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, m, Environment.TEST)
        HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

        when:
        client.toBlocking().exchange(HttpRequest.POST('/logout', ""))

        then:
        noExceptionThrown()

        when:
        client.toBlocking().exchange(HttpRequest.GET("/logout"))

        then:
        noExceptionThrown()

        cleanup:
        client.close()
        embeddedServer.close()
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsSpec')
    @Singleton
    static class CustomLogoutHandler implements LogoutHandler {
        @Override
        MutableHttpResponse<?> logout(HttpRequest<?> request) {
            return HttpResponse.ok()
        }
    }

    @Requires(property = 'spec.name', value = 'LogoutControllerAllowedMethodsSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}
