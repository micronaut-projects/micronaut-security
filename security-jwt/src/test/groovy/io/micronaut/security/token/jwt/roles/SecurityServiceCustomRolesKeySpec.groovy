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
package io.micronaut.security.token.jwt.roles

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.utils.SecurityService
import jakarta.inject.Singleton

class SecurityServiceCustomRolesKeySpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecurityServiceCustomRolesKeySpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.authentication': 'bearer',
            'micronaut.security.token.roles-name' : 'customRoles',
        ]
    }

    void "verify SecurityService.isCurrentUserInRole() with custom roleKey"() {
        when:
        Boolean hasRole = rolesRequest('ROLE_USER', "user2", "password")

        then:
        hasRole

        when:
        hasRole = rolesRequest('ROLE_ADMIN', "user2", "password")

        then:
        !hasRole
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'SecurityServiceCustomRolesKeySpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {

        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user2', ['ROLE_USER'])])
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
        Boolean roles(@Nullable String role, Authentication authentication) {
            assert authentication.getAttributes().containsKey("customRoles")
            assert !authentication.getAttributes().containsKey("roles")
            securityService.hasRole(role)
        }
    }

    private Boolean rolesRequest(String role, String username, String password) {
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials(username, password)
        BearerAccessRefreshToken loginRsp = client.retrieve(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        client.retrieve(HttpRequest.GET("/securityservicecustomroleskey/roles?role=" + role)
                .bearerAuth(loginRsp.accessToken), Boolean)
    }
}
