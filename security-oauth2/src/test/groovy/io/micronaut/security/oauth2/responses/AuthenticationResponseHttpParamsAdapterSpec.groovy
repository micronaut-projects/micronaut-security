package io.micronaut.security.oauth2.responses

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpParameters
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.endpoints.authorization.response.AuthorizationResponse
import io.micronaut.security.oauth2.state.State
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AuthenticationResponseHttpParamsAdapterSpec extends Specification {

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'micronaut.security.enabled': true,
            'spec.name': 'AuthenticationResponseHttpParamsAdapterSpec'
    ])

    @AutoCleanup
    @Shared
    HttpClient httpClient = embeddedServer.applicationContext.createBean( HttpClient, embeddedServer.URL)

    BlockingHttpClient getClient() {
        httpClient.toBlocking()
    }

    void "create authentication response"() {
        given:
        HttpRequest request = HttpRequest.GET('/oauthplayground/?code=4/JwFQJdJbxwRGC5Iylh92Ab-f1DgimwRyrKpVCn0W9kfovl8LOXcHr2NNyMpoovK3QlZS9p86WVtwbkk0ePmFoZ8&scope=https://www.googleapis.com/auth/cloud-platform%20https://www.googleapis.com/auth/cloud-translation')

        when:
        MockAuthenticationResponse authenticationResponse = client.retrieve(request, MockAuthenticationResponse)

        then:
        authenticationResponse.code == '4/JwFQJdJbxwRGC5Iylh92Ab-f1DgimwRyrKpVCn0W9kfovl8LOXcHr2NNyMpoovK3QlZS9p86WVtwbkk0ePmFoZ8'
    }

    @Requires(property = 'spec.name', value = 'AuthenticationResponseHttpParamsAdapterSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller('/oauthplayground')
    static class MockController {

        private final AuthenticationResponseFactory authenticationResponseFactory

        MockController(AuthenticationResponseFactory authenticationResponseFactory) {
            this.authenticationResponseFactory = authenticationResponseFactory
        }

        @Get("/")
        AuthorizationResponse index(HttpParameters httpParameters) {
            authenticationResponseFactory.create(httpParameters)
        }
    }

    static class MockAuthenticationResponse implements AuthorizationResponse {
        State state
        String code
    }

}
