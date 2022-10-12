package io.micronaut.security.oauth2.endpoint.endsession.request

import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.simple.SimpleHttpRequest
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.client.DefaultOpenIdClient
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.oauth2.keycloack.v16.Keycloak
import spock.lang.IgnoreIf

class KeycloakEndSessionEndpointSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'KeycloakEndSessionEndpointSpec'
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
    void "keycloak configuration supports endSession"() {
        given:
        String name = "keycloak"

        HttpRequest<?> request = new SimpleHttpRequest<>(HttpMethod.GET,
                "http://localhost:" + embeddedServer.port + "/oauth/logout", null)

        expect:
        applicationContext.containsBean(DefaultOpenIdClient, Qualifiers.byName(name))
        applicationContext.getBean(DefaultOpenIdClient, Qualifiers.byName(name)).supportsEndSession()
        applicationContext.getBean(DefaultOpenIdClient, Qualifiers.byName(name))
                .endSessionRedirect(request, Authentication.build("sherlock")).isPresent()

        when:
        String redirect = applicationContext.getBean(DefaultOpenIdClient, Qualifiers.byName(name))
                .endSessionRedirect(request, Authentication.build("sherlock"))
                .get()
                .getHeaders()
                .get(HttpHeaders.LOCATION)
                .toString()

        then:
        "http://localhost:" + Keycloak.port + "/auth/realms/master/protocol/openid-connect/logout?redirect_uri=http%3A%2F%2Flocalhost%3A" + embeddedServer.port + "%2Flogout" == redirect
    }
}
