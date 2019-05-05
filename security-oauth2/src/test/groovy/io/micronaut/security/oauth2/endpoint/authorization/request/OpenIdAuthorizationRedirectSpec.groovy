package io.micronaut.security.oauth2.endpoint.authorization.request

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.OpenIDIntegrationSpec
import io.micronaut.security.oauth2.client.OpenIdClient
import io.micronaut.security.oauth2.routes.OauthController

import java.nio.charset.StandardCharsets

class OpenIdAuthorizationRedirectSpec extends OpenIDIntegrationSpec {

    void "test authorization redirect with issuer with path"() {
        given:
        Map config = getConfiguration()
        config.put("micronaut.security.enabled", true)
        config.put("micronaut.security.token.jwt.enabled", true)
        config.put("micronaut.security.token.jwt.cookie.enabled", true)
        config.put("micronaut.security.oauth2.clients.keycloak.openid.issuer", ISSUER)
        config.put("micronaut.security.oauth2.clients.keycloak.client-id", "myclient")
        config.put("micronaut.security.oauth2.clients.keycloak.client-secret", CLIENT_SECRET)
        ApplicationContext context = startContext(config)
        EmbeddedServer embeddedServer = context.getBean(EmbeddedServer)
        embeddedServer.start()
        RxHttpClient client = context.createBean(RxHttpClient.class, embeddedServer.getURL(), new DefaultHttpClientConfiguration(followRedirects: false))

        expect:
        context.containsBean(OpenIdClient, Qualifiers.byName("keycloak"))
        context.containsBean(OauthController, Qualifiers.byName("keycloak"))

        when:
        HttpResponse response = client.toBlocking().exchange("/oauth/login/keycloak")
        String location = URLDecoder.decode(response.header(HttpHeaders.LOCATION), StandardCharsets.UTF_8.toString())

        then:
        response.status == HttpStatus.FOUND
        location.startsWith(ISSUER + "/protocol/openid-connect/auth")
        location.contains("scope=openid email profile")
        location.contains("response_type=code")
        location.contains("redirect_uri=http://localhost:" + embeddedServer.getPort() + "/oauth/callback/keycloak")
        location.contains("state={\"nonce\":\"")
        location.contains("client_id=myclient")

        cleanup:
        context.close()
    }

}
