package io.micronaut.security.oauth2.e2e

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.pages.HomePage
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.DefaultProviderResolver
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.request.DefaultAuthorizationRedirectHandler
import io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator
import io.micronaut.security.oauth2.keycloak.KeycloakAuthorizationRedirectHandler
import io.micronaut.security.oauth2.keycloak.KeycloakEndSessionEndpoint
import io.micronaut.security.oauth2.keycloak.KeycloakIssuerClaimValidator
import io.micronaut.security.oauth2.keycloak.KeycloakProviderResolver
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.oauth2.keycloak.docker.Keycloak
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.utils.BaseUrlUtils
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import org.testcontainers.DockerClientFactory
import spock.lang.IgnoreIf
import spock.lang.Shared

import java.security.Principal

@spock.lang.Requires({ DockerClientFactory.instance().isDockerAvailable() })
class OpenIdAuthorizationCodeSpec extends GebSpec {

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Override
    Browser getBrowser() {
        Browser browser = super.getBrowser()
        if (embeddedServer) {
            browser.baseUrl = BaseUrlUtils.getBaseUrl(embeddedServer)
        }
        browser
    }

    Map<String, Object> getConfiguration() {
        Map<String, Object> m = ConfigurationUtils.getConfiguration('OpenIdAuthorizationCodeSpec') + [
                'micronaut.security.authentication': 'cookie',
                "micronaut.security.token.jwt.signatures.secret.generator.secret" : 'pleaseChangeThisSecretForANewOne',
                "micronaut.security.endpoints.logout.get-allowed": true,
        ] as Map<String, Object>
        if (System.getProperty(Keycloak.SYS_TESTCONTAINERS) == null || Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS))) {
            m.putAll([
                    "micronaut.security.oauth2.clients.keycloak.openid.issuer" : Keycloak.issuer,
                    "micronaut.security.oauth2.clients.keycloak.client-id" : Keycloak.CLIENT_ID,
                    "micronaut.security.oauth2.clients.keycloak.client-secret" : Keycloak.clientSecret
            ])
        }
        m
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test a full login"() {
        when:
        browser.go "/oauth/login/keycloak"

        then:
        browser.at LoginPage

        and:
        !browser.driver.pageSource.contains("Invalid parameter: redirect_uri")

        when:
        LoginPage loginPage = browser.page LoginPage
        loginPage.login(Keycloak.TEST_USERNAME, Keycloak.TEST_PASSWORD)

        then:
        browser.at HomePage

        when:
        HomePage homePage = browser.page HomePage

        then:
        !homePage.message.contains("Hello anonymous")
        homePage.message.matches("Hello .*")

        when:
        browser.via OAuthLogoutPage

        then:
        browser.at HomePage

        when:
        homePage = browser.page HomePage

        then:
        homePage.message.contains("Hello anonymous")
    }

    @Requires(property = 'spec.name', value = 'OpenIdAuthorizationCodeSpec')
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class HomeController {
        @Get(produces = MediaType.TEXT_HTML)
        String index(@Nullable Principal principal) {
            "<html><head><title>Home</title></head><body>Hello ${principal ? principal.name : 'anonymous'}</body></html>"
        }
    }

    @Singleton
    @Named("keycloak")
    @Requires(property = 'spec.name', value = 'OpenIdAuthorizationCodeSpec')
    static class CustomEndSessionEndpoint extends KeycloakEndSessionEndpoint {
        CustomEndSessionEndpoint(@Named("keycloak") OpenIdProviderMetadata openIdProviderMetadata,
                                 EndSessionConfiguration endSessionConfiguration,
                                 HttpHostResolver httpHostResolver) {
            super(openIdProviderMetadata, endSessionConfiguration, httpHostResolver)
        }
    }

    @Singleton
    @Replaces(DefaultAuthorizationRedirectHandler.class)
    @Requires(property = 'spec.name', value = 'OpenIdAuthorizationCodeSpec')
    static class CustomDefaultAuthorizationRedirectHandler extends KeycloakAuthorizationRedirectHandler {
    }

    @Singleton
    @Replaces(IssuerClaimValidator.class)
    @Requires(property = 'spec.name', value = 'OpenIdAuthorizationCodeSpec')
    static class CustomIssuerClaimValidator extends KeycloakIssuerClaimValidator {
    }

    @Singleton
    @Replaces(DefaultProviderResolver.class)
    @Requires(property = 'spec.name', value = 'OpenIdAuthorizationCodeSpec')
    static class CustomDefaultProviderResolver extends KeycloakProviderResolver {
        CustomDefaultProviderResolver(List<OpenIdClientConfiguration> openIdClientConfigurations) {
            super(openIdClientConfigurations)
        }
    }
}
