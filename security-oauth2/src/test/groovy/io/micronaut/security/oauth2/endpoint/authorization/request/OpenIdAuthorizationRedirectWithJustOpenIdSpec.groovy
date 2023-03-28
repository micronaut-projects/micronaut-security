package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.oauth2.PKCEUtils
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.routes.OauthController
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import org.testcontainers.DockerClientFactory
import spock.lang.IgnoreIf
import spock.lang.Requires

import java.nio.charset.StandardCharsets

@Requires({ DockerClientFactory.instance().isDockerAvailable() })
class OpenIdAuthorizationRedirectWithJustOpenIdSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> m = super.configuration  + [
                'micronaut.security.oauth2.pkce.enabled': StringUtils.FALSE,
                'micronaut.security.authentication': 'cookie',
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
    void "test authorization redirect with just openid"() {
        given:
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
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        location.contains("client_id=$Keycloak.CLIENT_ID")
        and:
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
        HttpClientResponseException ex = thrown(HttpClientResponseException)
        ex.response.status.code == 401
    }
}
