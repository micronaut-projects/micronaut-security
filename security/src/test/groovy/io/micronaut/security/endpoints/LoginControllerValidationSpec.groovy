package io.micronaut.security.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
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
        client.exchange(HttpRequest.POST('/login', creds))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.BAD_REQUEST

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
        MutableHttpResponse<?> loginSuccess(UserDetails userDetails, HttpRequest<?> request) {
            HttpResponse.ok()
        }

        @Override
        MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed) {
            HttpResponse.unauthorized()
        }
    }
}
