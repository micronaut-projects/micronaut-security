package io.micronaut.security.oauth2.e2e

import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.ConfigurationFixture
import io.micronaut.security.oauth2.OpenIDIntegrationSpec

class OpenIdAuthorizationCodeSpec extends GebSpec implements OpenIDIntegrationSpec, ConfigurationFixture {

    void "test a full login"() {
        given:
        ApplicationContext context = startContext()
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer)
        embeddedServer.start()

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

    @Override
    Map<String, Object> getConfiguration() {
        OpenIDIntegrationSpec.super.getConfiguration() +
                oauth2Config +
                [
                        "micronaut.security.token.jwt.cookie.enabled" : true,
                        "micronaut.security.oauth2.clients.keycloak.openid.issuer" : ISSUER,
                        "micronaut.security.oauth2.clients.keycloak.client-id" : CLIENT_ID,
                        "micronaut.security.oauth2.clients.keycloak.client-secret" : CLIENT_SECRET,
                        "micronaut.security.token.jwt.signatures.secret.generator.secret" : 'pleaseChangeThisSecretForANewOne',
        ] as Map<String, Object>
    }

}
