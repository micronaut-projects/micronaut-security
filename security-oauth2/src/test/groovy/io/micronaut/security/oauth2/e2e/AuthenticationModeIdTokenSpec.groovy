package io.micronaut.security.oauth2.e2e

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.GebEmbeddedServerSpecification
import io.micronaut.security.oauth2.Keycloak
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature
import io.micronaut.security.token.validator.TokenValidator
import spock.lang.IgnoreIf

import java.security.Principal

@IgnoreIf({ sys['testcontainers'] == false })
class AuthenticationModeIdTokenSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'AuthenticationModeIdTokenSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'idtoken',
                "micronaut.security.oauth2.clients.keycloak.openid.issuer" : Keycloak.issuer,
                "micronaut.security.oauth2.clients.keycloak.client-id" : Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.keycloak.client-secret" : Keycloak.clientSecret,
        ] as Map<String, Object>
    }

    void "test a full login"() {
        given:
        browser.baseUrl = "http://localhost:${embeddedServer.port}"

        expect:
        applicationContext.containsBean(JwksSignature)
        applicationContext.containsBean(TokenValidator)

        when:
        go "/oauth/login/keycloak"

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login("user", "password")

        then:
        at HomePage

        when:
        HomePage homePage = browser.page HomePage

        then:
        homePage.message.matches("Hello .*")
    }

    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller
    static class HomeController {

        @Get(produces = MediaType.TEXT_HTML)
        String index(Principal principal) {
            "<html><head><title>Home</title></head><body>Hello ${principal.name}</body></html>"
        }
    }
}
