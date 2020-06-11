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
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.handlers.LoginHandler
import io.micronaut.security.token.config.TokenConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton

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
    static class CustomAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            return Flowable.create({emitter ->
                emitter.onNext(AuthenticationResponse.build("user", new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)

        }
    }
}
