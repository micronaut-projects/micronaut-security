package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.PKCEUtils
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import org.testcontainers.DockerClientFactory
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink
import spock.lang.IgnoreIf

import java.nio.charset.StandardCharsets
import java.util.regex.Pattern

@spock.lang.Requires({ DockerClientFactory.instance().isDockerAvailable() })
class OpenIdAuthorizationRedirectOauthDisabledSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OpenIdAuthorizationRedirectOauthDisabledSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = super.configuration + [
                'micronaut.security.authentication': 'cookie',
                'micronaut.security.oauth2.pkce.enabled': StringUtils.FALSE,
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url": "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id": Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.twitter.client-secret": "mysecret",
                "micronaut.security.oauth2.clients.twitter.enabled": false,
        ]
        if (System.getProperty(Keycloak.SYS_TESTCONTAINERS) == null || Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS))) {
            m.putAll([
                "micronaut.security.oauth2.clients.keycloak.openid.issuer": Keycloak.issuer,
                "micronaut.security.oauth2.clients.keycloak.client-id": Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.keycloak.client-secret": Keycloak.clientSecret,
            ])
        }
        m
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test authorization redirect with openid and oauth disabled"() {
        given:
        Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile('^[0-9a-zA-Z\\-\\.~_]+$')
        HttpClient client = applicationContext.createBean(HttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        applicationContext.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        !applicationContext.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        !applicationContext.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith(Keycloak.issuer + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("client_id=$Keycloak.CLIENT_ID")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")

        and: 'PKCE cookie is not present'
        !response.getCookie("OAUTH2_PKCE").isPresent()

        when:
        Map<String, String> queryValues = StateUtils.queryValuesAsMap(location)
        String state = StateUtils.decodeState(queryValues)
        then:
        state.contains('"nonce":"')
        state.contains('"redirectUri":"http://localhost:' + embeddedServer.getPort() + '/oauth/callback/keycloak"')

        and:
        !PKCEUtils.getCodeChallenge(queryValues)
        !PKCEUtils.getCodeChallengeMethod(queryValues)

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        HttpClientResponseException ex = thrown()
        ex.response.status.code == 401
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OpenIdAuthorizationRedirectOauthDisabledSpec")
    @Requires(property = "micronaut.security.oauth2.clients.twitter")
    static class TwitterAuthenticationMapper implements OauthAuthenticationMapper {

        @Override
        Publisher<Authentication> createAuthenticationResponse(TokenResponse tokenResponse, State state) {
            Flux.create({ emitter ->
                emitter.next(Authentication.build("twitterUser"))
                emitter.complete()
            }, FluxSink.OverflowStrategy.ERROR)
        }
    }
}
