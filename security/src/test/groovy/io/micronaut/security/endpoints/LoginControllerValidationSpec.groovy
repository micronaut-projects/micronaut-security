package io.micronaut.security.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.handlers.LoginHandler
import spock.lang.Unroll

import javax.inject.Singleton

class LoginControllerValidationSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LoginControllerValidationSpec'
    }

    @Unroll("{\"username\": \"#username\", \"password\": \"#password\"} is invalid payload")
    void "LoginController responds BAD_REQUEST if POJO sent to /login is invalid"(String username, String password) {
        given:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials(username, password)

        when:
        Argument<String> okArg = Argument.of(String)
        Argument<String> errorArgument = Argument.of(String)

        client.exchange(HttpRequest.POST('/login', creds), okArg, errorArgument)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.BAD_REQUEST

        when:
        Optional<String> errorOptional = e.response.getBody(String)

        then:
        errorOptional.isPresent()

        when:
        String jsonError = errorOptional.get()

        then:
        jsonError.contains('must not be blank') || jsonError.contains('must not be null')

        where:
        username | password
        null     | 'aabbc12345678'
        ''       | 'aabbc12345678'
        'johnny' | null
        'johnny' | ''
    }

    @Requires(property = 'spec.name', value = 'LoginControllerValidationSpec')
    @Singleton
    static class CustomLoginHandler implements LoginHandler {

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
