package io.micronaut.security.token.jwt.cookie

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpMethod
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import io.micronaut.security.testutils.ConfigurationFixture
import io.micronaut.security.testutils.ConfigurationUtils
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.jwt.endpoints.OauthController
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.utils.BaseUrlUtils
import io.micronaut.web.router.RouteMatch
import io.micronaut.web.router.Router
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import org.testcontainers.DockerClientFactory
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.IgnoreIf
import spock.lang.Shared

import java.util.concurrent.ConcurrentHashMap

@spock.lang.Requires({ DockerClientFactory.instance().isDockerAvailable() })
class OauthControllerEnabledSpec extends GebSpec {
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
        ConfigurationUtils.getConfiguration('OauthControllerEnabledSpec') + [
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.redirect.unauthorized.url': '/login/auth',
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
        ]
    }

    @Requires(property = "spec.name", value = "OauthControllerEnabledSpec")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = 'spec.name', value = 'OauthControllerEnabledSpec')
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        private final ConcurrentHashMap<String, Authentication> tokens = new ConcurrentHashMap<>()

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.computeIfAbsent(event.getRefreshToken(), (provider)  -> event.getAuthentication())
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            return Mono.just(tokens.computeIfPresent(refreshToken,
                    (s, auth) -> Authentication.build(auth.getName() + "-refreshed", auth.getAttributes())))
        }
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test the oauthcontroller is enabled"() {
        when:
        applicationContext.getBean(OauthController)

        then:
        noExceptionThrown()

        when:
        Optional<RouteMatch> match = applicationContext.getBean(Router).route(HttpMethod.GET, '/oauth/access_token')

        then:
        match.isPresent()
    }
}
