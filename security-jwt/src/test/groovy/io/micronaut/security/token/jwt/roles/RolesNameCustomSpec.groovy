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
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.utils.SecurityService
import jakarta.inject.Singleton

class RolesNameSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'RolesNameSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
            'micronaut.security.token.roles-name' : 'groups',
            'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
        ]
    }

    void "it is possible to specify the claim name which stores the roles"() {
        given: '''A JWT which maybe generated outside of Micronaut. 
This token is generated with the secret signature configuration to be able to validated the signature easily the test.
But in real life it maybe a token generated by a thirdparty authorization server. Thus, we have no control about the claims.
        '''
        JwtTokenGenerator tokenGenerator = applicationContext.getBean(JwtTokenGenerator)
        String jwt = tokenGenerator.generateToken([sub: 'john', groups: ['ROLE_NIGHT_WATCH']]).get()

        when:
        client.exchange(HttpRequest.GET('/nightwatch').bearerAuth(jwt))

        then:
        noExceptionThrown()

        when:
        client.exchange(HttpRequest.GET('/kingguard').bearerAuth(jwt))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.FORBIDDEN
    }

    @Requires(property = 'spec.name', value = 'RolesNameSpec')
    @Controller
    static class NightWatchController {
        @Produces(MediaType.TEXT_PLAIN)
        @Secured("ROLE_NIGHT_WATCH")
        @Get("/nightwatch")
        String nightwatch(Authentication authentication) {
            'You are a crow'
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Secured("ROLE_KING_GUARD")
        @Get("/kingguard")
        String kingguard(Authentication authentication) {
            'You are a white cloak'
        }
    }
}
