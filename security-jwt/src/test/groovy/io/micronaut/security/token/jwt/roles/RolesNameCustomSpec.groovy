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

import com.nimbusds.jwt.JWTParser
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.bearer.BearerEnabledSpec
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import jakarta.inject.Singleton

class RolesNameCustomSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'RolesNameCustomSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.token.roles-name' : 'groups',
            'micronaut.security.authentication'   : 'bearer',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]
    }

    void "it is possible to specify a different claim name to stores the roles in the JWT we generate"() {
        when:
        BearerAccessRefreshToken bearer = client.retrieve(HttpRequest.POST('/login', '{"username":"john","password":"elementary"}'), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        bearer
        bearer.accessToken

        and: 'there is a claim rolesKey because the value micronaut.security.token.roles-name is different than default'
        JWTParser.parse(bearer.accessToken).getJWTClaimsSet().getClaim("rolesKey") != null

        when:
        client.exchange(HttpRequest.GET('/nightwatch').bearerAuth(bearer.accessToken))

        then:
        noExceptionThrown()

        when:
        client.exchange(HttpRequest.GET('/kingguard').bearerAuth(bearer.accessToken))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.FORBIDDEN
    }

    @Requires(property = 'spec.name', value = 'RolesNameCustomSpec')
    @Controller
    static class NightWatchController {
        @Produces(MediaType.TEXT_PLAIN)
        @Secured("ROLE_NIGHT_WATCH")
        @Get("/nightwatch")
        String nightwatch() {
            'You are a crow'
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured("ROLE_KING_GUARD")
        @Get("/kingguard")
        String kingguard() {
            'You are a white cloak'
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'RolesNameCustomSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {

        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('john', ['ROLE_NIGHT_WATCH'])])
        }
    }
}
