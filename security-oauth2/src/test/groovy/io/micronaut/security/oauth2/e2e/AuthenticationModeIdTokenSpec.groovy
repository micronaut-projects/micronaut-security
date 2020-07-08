package io.micronaut.security.oauth2.e2e

import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.http.uri.UriBuilder
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.GebEmbeddedServerSpecification
import io.micronaut.security.oauth2.Keycloak
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata
import io.micronaut.security.oauth2.configuration.endpoints.EndSessionConfiguration
import io.micronaut.security.oauth2.endpoint.endsession.request.EndSessionEndpoint
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature
import io.micronaut.security.token.validator.TokenValidator
import spock.lang.IgnoreIf

import javax.inject.Named
import javax.inject.Singleton
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
                "micronaut.security.endpoints.logout.get-allowed": true,
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
    @Requires(property = 'spec.name', value = 'AuthenticationModeIdTokenSpec')
    static class KeycloakEndSessionEndpoint implements EndSessionEndpoint {

        public static final String PARAM_REDIRECT_URI = "redirect_uri"
        private final OpenIdProviderMetadata openIdProviderMetadata
        private final EndSessionConfiguration endSessionConfiguration
        private final HttpHostResolver httpHostResolver

        KeycloakEndSessionEndpoint(@Named("keycloak") OpenIdProviderMetadata openIdProviderMetadata,
                                   EndSessionConfiguration endSessionConfiguration,
                                   HttpHostResolver httpHostResolver) {
            this.openIdProviderMetadata = openIdProviderMetadata
            this.endSessionConfiguration = endSessionConfiguration
            this.httpHostResolver = httpHostResolver
        }

        @Nullable
        @Override
        String getUrl(HttpRequest originating, Authentication authentication) {
            (openIdProviderMetadata.getEndSessionEndpoint() == null) ? null :
                    UriBuilder.of(URI.create(openIdProviderMetadata.getEndSessionEndpoint()))
                            .queryParam(PARAM_REDIRECT_URI, httpHostResolver.resolve(originating) + endSessionConfiguration.getRedirectUri())
                            .build()
                            .toString()
        }
    }
}
