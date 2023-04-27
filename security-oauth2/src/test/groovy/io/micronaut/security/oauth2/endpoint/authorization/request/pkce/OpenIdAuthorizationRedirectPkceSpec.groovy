package io.micronaut.security.oauth2.endpoint.authorization.request.pkce

import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.PKCEUtils
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.endpoint.authorization.pkce.S256PkceGenerator
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.routes.OauthController
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
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
class OpenIdAuthorizationRedirectPkceSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'OpenIdAuthorizationRedirectPkceSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = super.configuration + [
                'micronaut.security.oauth2.pkce.enabled': StringUtils.TRUE,
                'micronaut.security.authentication': 'cookie',
                "micronaut.security.oauth2.clients.twitter.authorization.url": "https://twitter.com/authorize",
                "micronaut.security.oauth2.clients.twitter.token.url"        : "https://twitter.com/token",
                "micronaut.security.oauth2.clients.twitter.client-id"        : Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.twitter.client-secret"    : "mysecret",
        ]
        if (System.getProperty(Keycloak.SYS_TESTCONTAINERS) == null || Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS))) {
            m.putAll([
                    "micronaut.security.oauth2.clients.keycloak.openid.issuer"   : Keycloak.issuer,
                    "micronaut.security.oauth2.clients.keycloak.client-id"       : Keycloak.CLIENT_ID,
                    "micronaut.security.oauth2.clients.keycloak.client-secret"   : Keycloak.clientSecret,
            ])
        }
        m
    }

    @IgnoreIf({ System.getProperty(Keycloak.SYS_TESTCONTAINERS) != null && !Boolean.valueOf(System.getProperty(Keycloak.SYS_TESTCONTAINERS)) })
    void "test authorization redirect for openid and normal oauth"() {
        given:
        Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile('^[0-9a-zA-Z\\-\\.~_]+$')
        HttpClient client = applicationContext.createBean(HttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        applicationContext.findBean(OpenIdClient, Qualifiers.byName("keycloak")).isPresent()
        applicationContext.findBean(OauthClient, Qualifiers.byName("twitter")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("keycloak")).isPresent()
        applicationContext.findBean(OauthController, Qualifiers.byName("twitter")).isPresent()

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")

        then:
        noExceptionThrown()
        response.status == HttpStatus.FOUND

        when:
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        location.startsWith(Keycloak.issuer + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        location.contains("client_id=$Keycloak.CLIENT_ID")

        and: 'PKCE cookie is present'
        response.getCookie("OAUTH2_PKCE").isPresent()

        when:
        Map<String, String> queryValues = StateUtils.queryValuesAsMap(location)
        String state = StateUtils.decodeState(queryValues)

        then:
        state.contains('"nonce":"')
        state.contains('"redirectUri":"http://localhost:' + embeddedServer.getPort() + '/oauth/callback/keycloak"')

        when:
        String codeChallenge = PKCEUtils.getCodeChallenge(queryValues)
        String codeChallengeMethod = PKCEUtils.getCodeChallengeMethod(queryValues)

        then:
        codeChallenge
        VALID_CODE_CHALLENGE_PATTERN.matcher(codeChallenge)
        codeChallengeMethod == "S256"
        S256PkceGenerator.hash(response.getCookie("OAUTH2_PKCE").get().getValue()) == codeChallenge

        when:
        response = client.toBlocking().exchange("/oauth/login/twitter")
        location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith("https://twitter.com/authorize")
        !location.contains("scope=")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/twitter")
        location.contains("client_id=$Keycloak.CLIENT_ID")

        when:
        queryValues = StateUtils.queryValuesAsMap(location)
        state = StateUtils.decodeState(queryValues)

        then:
        state.contains('"nonce":"')
        state.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/twitter"')
    }

    @Singleton
    @Named("twitter")
    @Requires(property = "spec.name", value = "OpenIdAuthorizationRedirectPkceSpec")
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
