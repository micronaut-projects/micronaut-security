package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import javax.inject.Singleton

class IntrospectionEndpointSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'IntrospectionEndpointSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.authentication'   : 'bearer',
        ]
    }

    def "request to token_info responds with claims of access token JWT"() {
        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse loginRsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        loginRsp.status() == HttpStatus.OK
        loginRsp.body().accessToken

        when:
        String accessToken = loginRsp.body().accessToken
        HttpRequest request = HttpRequest.POST("/token_info", new IntrospectionRequest("XXX"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bearerAuth(accessToken)
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
        request = HttpRequest.POST("/token_info", new IntrospectionRequest(accessToken, "access_token"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bearerAuth(accessToken)
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
        introspectionResponse.exp
        introspectionResponse.exp > 0
        introspectionResponse.iat
        introspectionResponse.iat > 0
        introspectionResponse.nbf
        introspectionResponse.nbf > 0
        introspectionResponse.sub == 'user'
        introspectionResponse.iss
        !introspectionResponse.aud
        !introspectionResponse.jti
        introspectionResponse.extensions
        introspectionResponse.extensions['roles'] == ['ROLE_ADMIN', 'ROLE_USER']
        introspectionResponse.extensions['email'] == 'john@micronaut.io'

    }
    void "authenticated GET /token_info returns the user introspection"() {
        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse loginRsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        loginRsp.status() == HttpStatus.OK

        when:
        String accessToken = loginRsp.body().accessToken

        then:
        accessToken

        when:
        HttpRequest request = HttpRequest.GET("/token_info")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bearerAuth(accessToken)
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
        introspectionResponse.exp
        introspectionResponse.exp > 0
        introspectionResponse.iat
        introspectionResponse.iat > 0
        introspectionResponse.nbf
        introspectionResponse.nbf > 0
        introspectionResponse.sub == 'user'
        introspectionResponse.iss
        !introspectionResponse.aud
        !introspectionResponse.jti
        introspectionResponse.extensions
        introspectionResponse.extensions['roles'] == ['ROLE_ADMIN', 'ROLE_USER']
        introspectionResponse.extensions['email'] == 'john@micronaut.io'
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'IntrospectionEndpointSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                if (authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password') {
                    emitter.onNext(new UserDetails('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io']))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
        }
    }
}
