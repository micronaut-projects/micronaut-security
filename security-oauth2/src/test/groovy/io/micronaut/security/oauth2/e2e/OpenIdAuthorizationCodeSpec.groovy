package io.micronaut.security.oauth2.e2e

import io.micronaut.security.oauth2.GebEmbeddedServerSpecification
import io.micronaut.security.oauth2.Keycloak
import spock.lang.IgnoreIf

@IgnoreIf({ sys['testcontainers'] == false })
class OpenIdAuthorizationCodeSpec extends GebEmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'cookie',
                "micronaut.security.oauth2.clients.keycloak.openid.issuer" : Keycloak.issuer,
                "micronaut.security.oauth2.clients.keycloak.client-id" : Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.keycloak.client-secret" : Keycloak.clientSecret,
                "micronaut.security.token.jwt.signatures.secret.generator.secret" : 'pleaseChangeThisSecretForANewOne',
        ] as Map<String, Object>
    }

    void "test a full login"() {
        given:
        browser.baseUrl = "http://localhost:${embeddedServer.port}"

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
}
