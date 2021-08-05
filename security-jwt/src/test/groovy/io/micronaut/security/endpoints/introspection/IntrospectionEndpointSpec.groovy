package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import jakarta.inject.Singleton

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
        client.exchange(request, IntrospectionResponse)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when:
        HttpResponse<IntrospectionResponse> rsp = client.exchange(request.bearerAuth(accessToken), IntrospectionResponse)

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
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new  SuccessAuthenticationScenario('user', ['ROLE_ADMIN', 'ROLE_USER'], [email: 'john@micronaut.io'])])
        }
    }
}
