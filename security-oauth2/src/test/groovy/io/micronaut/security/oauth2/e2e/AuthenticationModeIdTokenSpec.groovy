package io.micronaut.security.oauth2.e2e

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.DefaultProviderResolver
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.request.DefaultAuthorizationRedirectHandler
import io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator
import io.micronaut.security.oauth2.keycloak.KeycloakAuthorizationRedirectHandler
import io.micronaut.security.oauth2.keycloak.KeycloakIssuerClaimValidator
import io.micronaut.security.oauth2.keycloak.KeycloakEndSessionEndpoint
import io.micronaut.security.oauth2.keycloak.KeycloakProviderResolver
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.GebEmbeddedServerSpecification
import io.micronaut.security.testutils.Keycloak
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature
import io.micronaut.security.token.validator.TokenValidator
import spock.lang.IgnoreIf

import javax.inject.Named
import javax.inject.Singleton
import java.security.Principal

class AuthenticationModeIdTokenSpec extends GebEmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'AuthenticationModeIdTokenSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        Map m = super.configuration + [
                'micronaut.security.authentication'              : 'idtoken',
                "micronaut.security.endpoints.logout.get-allowed": true,
        ] as Map<String, Object>
        if ((System.getProperty(Keycloak.SYS_TESTCONTAINERS) == null) || Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS))) {
            m.putAll([    "micronaut.security.oauth2.clients.keycloak.openid.issuer" : Keycloak.issuer,
                          "micronaut.security.oauth2.clients.keycloak.client-id" : Keycloak.CLIENT_ID,
                          "micronaut.security.oauth2.clients.keycloak.client-secret" : Keycloak.clientSecret,
            ] as Map<String, Object>)
        }
        m
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test a full login"() {
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
        !homePage.message.contains("Hello anonymous")
        homePage.message.matches("Hello .*")

        when:
        via OAuthLogoutPage

        then:
        at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.message.contains("Hello anonymous")
    }

    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    @Singleton
    @Named("keycloak")
    static class CustomEndSessionEndpoint extends KeycloakEndSessionEndpoint {

        CustomEndSessionEndpoint(@Named("keycloak") OpenIdProviderMetadata openIdProviderMetadata,
                                 EndSessionConfiguration endSessionConfiguration,
                                 HttpHostResolver httpHostResolver) {
            super(openIdProviderMetadata, endSessionConfiguration, httpHostResolver)
        }
    }

    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class HomeController {

        @Get(produces = MediaType.TEXT_HTML)
        String index(@Nullable Principal principal) {
            "<html><head><title>Home</title></head><body>Hello ${principal ? principal.name : 'anonymous'}</body></html>"
        }
    }

    @Singleton
    @Replaces(DefaultAuthorizationRedirectHandler.class)
    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    static class CustomDefaultAuthorizationRedirectHandler extends KeycloakAuthorizationRedirectHandler {
    }

    @Singleton
    @Replaces(IssuerClaimValidator.class)
    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    static class CustomIssuerClaimValidator extends KeycloakIssuerClaimValidator {
    }

    @Singleton
    @Replaces(DefaultProviderResolver.class)
    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    static class CustomDefaultProviderResolver extends KeycloakProviderResolver {
        CustomDefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations) {
            super(openIdClientConfigurations)
        }
    }
}
