package io.micronaut.security.oauth2.docs.managementendpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.*
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.reactivex.Maybe
import org.reactivestreams.Publisher

import jakarta.inject.Singleton

class LoggersSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LoggersSpec'
    }

    @Override
    String getOpenIdClientName() {
        'github'
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
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            return Maybe.<AuthenticationResponse>create(emitter -> {
                if (authenticationRequest.identity == "user" && authenticationRequest.secret == "password") {
                    emitter.onSuccess(new UserDetails("user", []))
                } else if (authenticationRequest.identity == "system" && authenticationRequest.secret == "password") {
                    emitter.onSuccess(new UserDetails("admin", ['ROLE_SYSTEM']))
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }
            }).toFlowable()
        }
    }
}
