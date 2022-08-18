package io.micronaut.security.token.jwt.cookie

import io.micronaut.security.testutils.GebEmbeddedServerSpecification
import io.micronaut.security.testutils.Keycloak
import spock.lang.IgnoreIf

class JwtCookiePriorLoginSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'JwtCookieAuthenticationSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.prior-to-login': true,
                'micronaut.security.redirect.unauthorized.url': '/login/auth',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test prior login behavior"() {
        when:
        go '/secured'

        then:
        at LoginPage

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login('sherlock', 'password')

        then:
        at SecuredPage
    }
}
