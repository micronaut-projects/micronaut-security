package io.micronaut.security.oauth2.e2e

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.client.IdTokenClaimsValidator
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint
import io.micronaut.security.oauth2.endpoint.endsession.request.KeycloakEndSessionEndpoint
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder
import io.micronaut.security.pages.HomePage
import io.micronaut.security.pages.KeycloakLogoutConfirmPage
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.DefaultProviderResolver
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.request.DefaultAuthorizationRedirectHandler
import io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator
import io.micronaut.security.oauth2.keycloak.KeycloakAuthorizationRedirectHandler
import io.micronaut.security.oauth2.keycloak.KeycloakIssuerClaimValidator
import io.micronaut.security.oauth2.keycloak.KeycloakProviderResolver
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.oauth2.keycloak.docker.Keycloak
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.testutils.TestContainersUtils
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.security.utils.BaseUrlUtils
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import org.testcontainers.DockerClientFactory
import spock.lang.IgnoreIf
import spock.lang.Shared
import java.security.Principal
import java.util.function.Supplier

@spock.lang.Requires({ DockerClientFactory.instance().isDockerAvailable() })
class AuthenticationModeIdTokenSpec extends GebSpec {
    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Shared
    ApplicationContext applicationContext = embeddedServer.applicationContext

    @Override
    Browser getBrowser() {
        Browser browser = super.getBrowser()
        if (embeddedServer) {
            browser.baseUrl = BaseUrlUtils.getBaseUrl(embeddedServer)
        }
        browser
    }


    Map<String, Object> getConfiguration() {
        Map<String, Object> m = ConfigurationUtils.getConfiguration('AuthenticationModeIdTokenSpec') + [
                'micronaut.security.authentication'              : 'idtoken',
                "micronaut.security.endpoints.logout.get-allowed": true,
                // ADDED: Persist the ID Token so it is available for the Logout Hint
                "micronaut.security.oauth2.openid.additional-claims.jwt": true,
        ] as Map<String, Object>
        if ((System.getProperty(Keycloak.SYS_TESTCONTAINERS) == null) || Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS))) {
            m.putAll([    "micronaut.security.oauth2.clients.keycloak.openid.issuer": Keycloak.issuer,
                          "micronaut.security.oauth2.clients.keycloak.client-id" : Keycloak.CLIENT_ID,
                          "micronaut.security.oauth2.clients.keycloak.client-secret" : Keycloak.clientSecret,
            ] as Map<String, Object>)
        }
        m
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test a full login"() {
        expect:
        applicationContext.containsBean(ReactiveJwksSignature)
        applicationContext.containsBean(TokenValidator)

        when: "Navigating to the Keycloak login endpoint"
        go "/oauth/login/keycloak"

        then: "We should be redirected to the Keycloak Login Page"
        waitFor(5) { at LoginPage }

        when: "We submit valid credentials"
        LoginPage loginPage = browser.page LoginPage
        loginPage.login(Keycloak.TEST_USERNAME, Keycloak.TEST_PASSWORD)

        then: "We should be redirected back to the Home Page"

        waitFor(5) { at HomePage }

        when: "We inspect the HomePage content"
        HomePage homePage = browser.page HomePage

        then: "The user is authenticated"
        !homePage.message.contains("Hello anonymous")
        homePage.message.matches("Hello .*")

        when: "We log out"
        via OAuthLogoutPage

        then: "Either we are back home, or Keycloak asks for confirmation"

        waitFor(5) { browser.isAt(HomePage) || browser.isAt(KeycloakLogoutConfirmPage) }

        when: "If Keycloak requires confirmation, confirm it"
        if (browser.isAt(KeycloakLogoutConfirmPage)) {
            page(KeycloakLogoutConfirmPage).confirm()
        }

        then: "We are redirected back home as anonymous"

        waitFor(5) { at HomePage  }

        when:
        homePage = browser.page HomePage

        then:
        homePage.message.contains("Hello anonymous")
    }

    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    @Replaces(IdTokenClaimsValidator.class)
    @Singleton
    static class IdTokenClaimsValidatorReplacement extends IdTokenClaimsValidator {
        IdTokenClaimsValidatorReplacement(Collection<OauthClientConfiguration> oauthClientConfigurations) {
            super(oauthClientConfigurations)
        }

        @Override
        @NonNull
        protected Optional<Boolean> matchesIssuer(@NonNull OpenIdClientConfiguration openIdClientConfiguration,
                                                  @NonNull String iss) {
            return openIdClientConfiguration.getIssuer()
                    .map(URL::toString)
                    .map(issuer -> {
                        return issuer.equalsIgnoreCase(iss) || issuer.replace(Keycloak.LOCALHOST, Keycloak.HOST_TESTCONTAINERS_INTERNAL).equalsIgnoreCase(iss)
                    })
        }
    }


    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    @Singleton
    @Named("keycloak")
    @Replaces(bean = EndSessionEndpoint, named = "keycloak")
    static class TestcontainersKeycloakEndSessionEndpoint extends KeycloakEndSessionEndpoint {

        TestcontainersKeycloakEndSessionEndpoint(EndSessionCallbackUrlBuilder builder,
                                                 @Named("keycloak") OauthClientConfiguration cfg,
                                                 @Named("keycloak") OpenIdProviderMetadata md) {
            super(builder, cfg, (Supplier<OpenIdProviderMetadata>) { -> md })
        }

        @Override
        String getUrl(HttpRequest<?> originating, Authentication authentication) {
            def url = super.getUrl(originating, authentication)
            if (!url) return null

            def v = System.getProperty(Keycloak.SYS_TESTCONTAINERS)
            def rewrite = (v == null || Boolean.valueOf(v))
            if (rewrite) {
                return url.replace("localhost", TestContainersUtils.getHost())
            }
            return url
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
