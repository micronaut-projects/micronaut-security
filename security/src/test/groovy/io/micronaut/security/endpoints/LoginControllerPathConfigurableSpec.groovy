/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.endpoints

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.handlers.LoginHandler
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

class LoginControllerPathConfigurableSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'LoginControllerPathConfigurableSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.endpoints.login.path': '/auth',
        ]
    }

    void "LoginController is not accessible at /login but at /auth"() {
        given:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')

        when:
        client.exchange(HttpRequest.POST('/login', creds))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED

        when:
        client.exchange(HttpRequest.POST('/auth', creds))

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'LoginControllerPathConfigurableSpec')
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

    @Requires(property = 'spec.name', value = 'LoginControllerPathConfigurableSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}
