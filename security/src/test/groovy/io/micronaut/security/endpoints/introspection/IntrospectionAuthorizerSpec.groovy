package io.micronaut.security.endpoints.introspection

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.AuthenticationUserDetailsAdapter
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.validator.TokenValidator
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.Unroll

import javax.inject.Singleton

class IntrospectionAuthorizerSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'IntrospectionAuthorizerSpec'
    }

    private HttpRequest introspectionEndpointRequestWithBasicAuth(String token) {
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
        m.keySet().sort() == ['active', 'username', 'roles', 'email'].sort()
        m['active'] == true
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
        Publisher<Authentication> validateToken(String token) {
            validateToken(token, null)
        }

        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            UserDetails ud = new UserDetails('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io'])
            Authentication authentication = new AuthenticationUserDetailsAdapter(ud, TokenConfiguration.DEFAULT_ROLES_NAME, TokenConfiguration.DEFAULT_NAME_KEY)
            if (token == "2YotnFZFEjr1zCsicMWpAA") {
                return Flowable.just(authentication)
            }
            return Flowable.empty()
        }
    }

    @Requires(property = 'spec.name', value = 'IntrospectionAuthorizerSpec')
    @Singleton
    static class MockAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            return Flowable.create(emitter -> {
                emitter.onNext(new UserDetails('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io']))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
}
