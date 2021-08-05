package io.micronaut.security.oauth2.docs.managementendpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import jakarta.inject.Singleton

class LoggersSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LoggersSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'endpoints.loggers.enabled': true,
            'endpoints.loggers.sensitive': true,
            'endpoints.health.enabled': true,
            'endpoints.health.sensitive': false,
        ]
    }

    void "/health endpoint is not secured"() {
        when:
        HttpResponse<?> response = client.exchange(HttpRequest.GET('/health'))

        then:
        noExceptionThrown()
        response.status() == HttpStatus.OK
    }

    void "/loggers endpoint is secured"() {
        when:
        client.exchange(HttpRequest.GET('/loggers'))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "/loggers endpoint is accessible for users with role ROLE_SYSTEM"() {
        given:
        HttpRequest<?> request = HttpRequest.GET('/loggers').basicAuth('system', 'password')

        when:
        HttpResponse<Map> response = client.exchange(request, Map)

        then:
        noExceptionThrown()
        response.status() == HttpStatus.OK

        when:
        Map m = response.body()

        then:
        m.containsKey('levels')
        m.containsKey('loggers')
    }

    void "/loggers endpoint is not accessible for users without role ROLE_SYSTEM"() {
        when:
        client.exchange(HttpRequest.GET('/loggers').basicAuth('user', 'password'))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.FORBIDDEN
    }

    @Requires(property = 'spec.name', value = 'LoggersSpec')
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user'), new SuccessAuthenticationScenario('system', ['ROLE_SYSTEM'])])
        }
    }
}
