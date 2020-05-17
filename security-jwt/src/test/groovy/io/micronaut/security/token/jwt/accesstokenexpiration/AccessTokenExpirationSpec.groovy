package io.micronaut.security.token.jwt.accesstokenexpiration

import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.testutils.EmbeddedServerSpecification

class AccessTokenExpirationSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'accesstokenexpiration'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
                'micronaut.security.endpoints.login.enabled': true,
                'micronaut.security.token.jwt.generator.access-token.expiration': 5,
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne'
        ]
    }

    def "expired access tokens failed validation"() {
        when:
        def creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken

        when:
        final String accessToken =  rsp.body().accessToken
        HttpRequest request = HttpRequest.GET("/beans").header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
        client.exchange(request)

        then:
        noExceptionThrown()

        when: 'sleep six seconds to leave time to the access token to expire'
        sleep(6_000)
        client.exchange(request)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }
}
