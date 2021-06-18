package io.micronaut.security.endpoints.introspection

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification
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
import jakarta.inject.Singleton

class IntrospectionControllerSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'IntrospectionControllerSpec'
    }

    void "post /token_info is secured"() {
        when: 'invalid introspection request'
        HttpRequest request = HttpRequest.POST("/token_info", new IntrospectionRequest("2YotnFZFEjr1zCsicMWpAA"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        client.exchange(request, Map)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "request to token_info responds with extensions"() {
        expect:
        applicationContext.containsBean(TokenValidator)

        when: 'invalid introspection request'
        HttpRequest request = HttpRequest.POST("/token_info", new IntrospectionRequest())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth('user', 'password')
        client.exchange(request, Map)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.BAD_REQUEST

        when:
        request = HttpRequest.POST("/token_info", new IntrospectionRequest("XXX"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth('user', 'password')
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
        request = HttpRequest.POST("/token_info", new IntrospectionRequest("2YotnFZFEjr1zCsicMWpAA"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth('user', 'password')
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

        when:
        HttpResponse<IntrospectionResponse> rsp = client.exchange(request, IntrospectionResponse)

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK

        when:
        IntrospectionResponse introspectionResponse = rsp.body()

        then:
        introspectionResponse.username == 'user'
        introspectionResponse.active
        !introspectionResponse.tokenType
        !introspectionResponse.scope
        !introspectionResponse.clientId
        !introspectionResponse.tokenType
        !introspectionResponse.exp
        !introspectionResponse.iat
        !introspectionResponse.nbf
        !introspectionResponse.sub
        !introspectionResponse.aud
        !introspectionResponse.iss
        !introspectionResponse.jti
        introspectionResponse.extensions
        introspectionResponse.extensions['roles'] == ['ROLE_ADMIN', 'ROLE_USER']
        introspectionResponse.extensions['email'] == 'john@micronaut.io'
    }

    @Requires(property = 'spec.name', value = 'IntrospectionControllerSpec')
    @Singleton
    static class CustomTokenValidator implements TokenValidator {

        @Override
        Publisher<Authentication> validateToken(String token, @Nullable HttpRequest<?> request) {
            UserDetails ud = new UserDetails('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io'])
            Authentication authentication = new AuthenticationUserDetailsAdapter(ud, TokenConfiguration.DEFAULT_ROLES_NAME, TokenConfiguration.DEFAULT_NAME_KEY)
            if (token == "2YotnFZFEjr1zCsicMWpAA") {
                return Flowable.just(authentication)
            }
            return Flowable.empty()
        }
    }

    @Requires(property = 'spec.name', value = 'IntrospectionControllerSpec')
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
