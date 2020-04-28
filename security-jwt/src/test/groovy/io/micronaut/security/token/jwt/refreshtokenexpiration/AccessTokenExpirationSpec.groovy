package io.micronaut.security.token.jwt.refreshtokenexpiration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AccessTokenExpirationSpec extends Specification {

    @Shared
    @AutoCleanup
    ApplicationContext context = ApplicationContext.run(
            [
                    'spec.name': 'refreshtokenexpiration',
                    'endpoints.beans.enabled': true,
                    'endpoints.beans.sensitive': true,
                    'micronaut.security.endpoints.login.enabled': true,
                    'micronaut.security.token.jwt.generator.access-token.expiration': 5,
                    'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne'
            ], Environment.TEST)

    @Shared
    EmbeddedServer embeddedServer = context.getBean(EmbeddedServer).start()

    @Shared
    @AutoCleanup
    HttpClient client = context.createBean(HttpClient, embeddedServer.getURL())


    def "expired access tokens failed validation"() {
        when:
        def creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = client.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when: 'sleep six seconds to leave time to the refresh token to expire'
        sleep(6_000)
        client.toBlocking().exchange(HttpRequest.GET("/secured")
                .bearerAuth(rsp.body().accessToken), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    @Requires(property = "spec.name", value = "refreshtokenexpiration")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/secured")
    static class SecuredController {

        @Get("/")
        String test() {
            "test"
        }
    }
}
