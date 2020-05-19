package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.oauth2.EmbeddedServerSpecification
import io.micronaut.security.oauth2.Keycloak
import io.micronaut.security.oauth2.StateUtils
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.routes.OauthController
import spock.lang.IgnoreIf

import java.nio.charset.StandardCharsets

@IgnoreIf({ sys['testcontainers'] == false })
class OpenIdAuthorizationRedirectWithJustOpenIdSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        Keycloak.init()
        super.configuration  + [
                "micronaut.security.token.jwt.cookie.enabled": true,
                "micronaut.security.oauth2.clients.keycloak.openid.issuer": Keycloak.issuer,
                "micronaut.security.oauth2.clients.keycloak.client-id": Keycloak.CLIENT_ID,
                "micronaut.security.oauth2.clients.keycloak.client-secret": Keycloak.clientSecret,
        ]
    }

    void "test authorization redirect with just openid"() {
        given:
        RxHttpClient client = applicationContext.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

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
        String parsedLocation = StateUtils.stateParser(location)
        parsedLocation.contains('"nonce":"')
        parsedLocation.contains('"redirectUri":"http://localhost:'+ embeddedServer.getPort() + '/oauth/callback/keycloak"')
        location.contains("client_id=$Keycloak.CLIENT_ID")

        when:
        client.toBlocking().exchange("/oauth/login/twitter")

        then:
        def ex = thrown(HttpClientResponseException)
        ex.response.status.code == 401
    }
}
