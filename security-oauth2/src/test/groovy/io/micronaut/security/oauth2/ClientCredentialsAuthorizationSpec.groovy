/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod
import io.micronaut.security.oauth2.grants.GrantType
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class ClientCredentialsAuthorizationSpec extends Specification {

    @Shared
    int dynamicPort = SocketUtils.findAvailableTcpPort()

    @Shared
    Map<String, Object> serverConf = [
            'micronaut.security.enabled'                                            : 'true',
            'micronaut.security.oauth2.enabled'                                     : 'true',
            'micronaut.security.token.jwt.enabled'                                  : 'true',
            'micronaut.security.oauth2.clients.authservice.grantType'               : GrantType.CLIENT_CREDENTIALS,
            'micronaut.security.oauth2.clients.authservice.introspection.authMethod': AuthenticationMethod.NONE,
            'micronaut.security.oauth2.clients.authservice.introspection.url'       : "http://localhost:${dynamicPort}/auth/token/introspection",
            'micronaut.server.port'                                                 : dynamicPort,
            'mockserver.path'                                                       : ''
    ]


    @AutoCleanup
    @Shared
    def server = ApplicationContext.run(EmbeddedServer, serverConf)


    def "verify server oauth authorization and authentication"() {
        given:
        def client = server.getApplicationContext().createBean(RxHttpClient.class, server.getURL())

        when:
        def response = client.toBlocking().retrieve(HttpRequest.GET('/oauth2/client-credentials')
                                                            .bearerAuth('822d2c97-e8b4-44b7-bc79-b89827a5ea87'))

        then:
        response == 'succeed'
    }

    def "verify authorization by oauth scope"() {
        given:
        def client = server.getApplicationContext().createBean(RxHttpClient.class, server.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        when:
        def response = client.toBlocking().retrieve(HttpRequest.GET('/oauth2/client-credentials/scope-read')
                                                            .bearerAuth('822d2c97-e8b4-44b7-bc79-b89827a5ea87'))

        then:
        response == 'succeed'
    }

    def "verify access forbidden with missing scope"() {
        given:
        def client = server.getApplicationContext().createBean(RxHttpClient.class, server.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        when:
        //todo is it a bug that exception thrown here at all?
        def response = client.toBlocking().exchange(HttpRequest.GET('/oauth2/client-credentials/scope-missing')
                                                            .bearerAuth('822d2c97-e8b4-44b7-bc79-b89827a5ea87'))

        then:
        HttpClientResponseException exception = thrown()
        exception.getStatus() == HttpStatus.FORBIDDEN
    }

    @Controller("/auth/token/introspection")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class TokenIntrospectionController {

        @Post("/")
        String introspectToken(@Body Map<String, String> body) {
            return """
            {
                  "active": true,
                  "client_id": "l238j323ds-23ij4",
                  "username": "jdoe",
                  "scope": "read write dolphin",
                  "sub": "Z5O3upPC88QrAjx00dis",
                  "aud": "https://protected.example.net/resource",
                  "iss": "https://server.example.com/",
                  "exp": 1419356238,
                  "iat": 1419350238,
                  "extension_field": "twenty-seven"
                 }
            """
        }
    }


    @Controller('/oauth2/client-credentials')
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class OauthController {

        @Get
        String noScope() {
            return "succeed"
        }

        @Get("/scope-read")
        @Secured("read")
        String readScope() {
            return "succeed"
        }

        @Get("/scope-missing")
        @Secured("missing")
        String missingScope() {
            return "succeed"
        }
    }
}
