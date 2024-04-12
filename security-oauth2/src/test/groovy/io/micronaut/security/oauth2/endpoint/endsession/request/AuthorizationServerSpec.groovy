package io.micronaut.security.oauth2.endpoint.endsession.request

import spock.lang.Specification
import spock.lang.Unroll

class AuthorizationServerSpec extends Specification {

    @Unroll("#authorizationServer is inferred for #issuer")
    void "Infer authorization server based on the issuer url"(String issuer, AuthorizationServer authorizationServer) {
        expect:
        authorizationServer == AuthorizationServer.infer(issuer).get()

        where:
        issuer                                                || authorizationServer
        "http://localhost:8180/auth/realms/master"            || AuthorizationServer.KEYCLOAK
        "http://localhost:8180/realms/master"                 || AuthorizationServer.KEYCLOAK
        "https://dev-XXXXX.oktapreview.com/oauth2/default"    || AuthorizationServer.OKTA
        "https://cognito-idp.us-east-1.amazonaws.com/12345}/" || AuthorizationServer.COGNITO
        "https://micronautguides.eu.auth0.com"                || AuthorizationServer.AUTH0
    }

    void "Infer authorization server based on the issuer url may return empty Optional"() {
        expect:
        !AuthorizationServer.infer("http://localhost:8180/auth").isPresent()
    }
}
