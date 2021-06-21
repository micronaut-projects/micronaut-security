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
package io.micronaut.security.utils

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.rules.SecurityRule
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import jakarta.inject.Singleton

class SecurityServiceCustomRolesKeySpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecurityServiceCustomRolesKeySpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.token.roles-name' : 'customRoles',
        ]
    }

    void "verify SecurityService.isCurrentUserInRole() with custom roleKey"() {
        when:
        Boolean hasRole = client.retrieve(rolesRequest('ROLE_USER', "user2", "password"), Boolean)

        then:
        hasRole

        when:
        hasRole = client.retrieve(rolesRequest('ROLE_ADMIN', "user2", "password"), Boolean)

        then:
        !hasRole

        when:
        hasRole = client.retrieve(rolesRequest('ROLE_USER', "user3", "password"), Boolean)

        then:
        !hasRole
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'SecurityServiceCustomRolesKeySpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest,
                                                       AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({emitter ->
                if ( authenticationRequest.identity == 'user2' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', [], [customRoles: ['ROLE_USER']]))
                } else if ( authenticationRequest.identity == 'user3' && authenticationRequest.secret == 'password' ) {
                    emitter.onNext(new UserDetails('user', [], [otherCustomRoles: ['ROLE_USER']]))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
        }
    }

    @Requires(property = 'spec.name', value = 'SecurityServiceCustomRolesKeySpec')
    @Controller("/securityservicecustomroleskey")
    static class SecurityServiceController {

        private final SecurityService securityService

        SecurityServiceController(SecurityService securityService) {
            this.securityService = securityService
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/roles{?role}")
        Boolean roles(@Nullable String role) {
            securityService.hasRole(role)
        }
    }

    private HttpRequest rolesRequest(String role, String username, String password) {
        HttpRequest.GET("/securityservicecustomroleskey/roles?role=" + role)
                .basicAuth(username, password)
    }
}
