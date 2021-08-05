package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.token.validator.TokenValidator
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import spock.lang.Unroll

class IntrospectionAuthorizerSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'IntrospectionAuthorizerSpec'
    }

    private static HttpRequest introspectionEndpointRequestWithBasicAuth(String token) {
        HttpRequest.POST("/token_info", new IntrospectionRequest(token))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth("user", "password")
    }

    def "you can provide an introspection authorizer to validate the request"() {
        when:
        HttpRequest request = introspectionEndpointRequestWithBasicAuth("XXX")
        HttpResponse<Map> response = client.exchange(request, Map)

        then:
        noExceptionThrown()
        response.status() == HttpStatus.OK

        when:
        Map m = response.body()

        then:
        m.keySet() == ['active'] as Set<String>
        m['active'] == false

        when:
        request = introspectionEndpointRequestWithBasicAuth("2YotnFZFEjr1zCsicMWpAA")
        response = client.exchange(request, Map)

        then:
        noExceptionThrown()
        response.status() == HttpStatus.OK

        when:
        m = response.body()

        then:
        m.keySet().sort() == ['active', 'sub', 'username', 'roles', 'email'].sort()
        m['active'] == true
        m['sub'] == 'user'
        m['username'] == 'user'
        m['roles'] == ['ROLE_ADMIN', 'ROLE_USER']
        m['email'] == 'john@micronaut.io'
    }

    @Unroll("For HTTP Header Authorization: #authorization IntrospectionEndpointAuthorizer returns false")
    void "if the IntrospectionEndpointAuthorizer returns false the introspection endpoint returns 401"(String authorization) {
        when:
        HttpRequest request = HttpRequest.POST("/token_info", new IntrospectionRequest("2YotnFZFEjr1zCsicMWpAA"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, authorization)
        client.exchange(request, Map)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        where:
        authorization << ['', '123', 'Basic', 'Basic ', 'Foooo dXNlcjpwYXNzd29yZA==']
    }

    @Requires(property = 'spec.name', value = 'IntrospectionAuthorizerSpec')
    @Singleton
    static class CustomTokenValidator implements TokenValidator {

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            Authentication authentication = Authentication.build('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io'])
            if (token == "2YotnFZFEjr1zCsicMWpAA") {
                return Flux.just(authentication)
            }
            return Flux.empty()
        }
    }

    @Requires(property = 'spec.name', value = 'IntrospectionAuthorizerSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io'])])
        }
    }
}
