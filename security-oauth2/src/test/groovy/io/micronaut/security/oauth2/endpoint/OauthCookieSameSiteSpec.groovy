package io.micronaut.security.oauth2.endpoint

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.cookie.SameSite
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.cookie.CookiePkcePersistenceConfiguration
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.cookie.CookieStatePersistenceConfiguration
import io.micronaut.security.oauth2.endpoint.nonce.persistence.cookie.CookieNoncePersistenceConfiguration
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class OauthCookieSameSiteSpec extends Specification {

    @Shared
    @AutoCleanup
    EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerOauthCookieSameSiteSpec",
    ] as Map<String, Object>)

    void "SameSite is not set on the state, PKCE and nonce cookies by default"() {
        given:
        EmbeddedServer server = startServer([:])
        BlockingHttpClient client = server.applicationContext.createBean(HttpClient, server.URL).toBlocking()

        expect:
        !server.applicationContext.getBean(CookieStatePersistenceConfiguration).cookieSameSite.isPresent()
        !server.applicationContext.getBean(CookiePkcePersistenceConfiguration).cookieSameSite.isPresent()
        !server.applicationContext.getBean(CookieNoncePersistenceConfiguration).cookieSameSite.isPresent()

        when:
        Map<String, String> setCookies = loginSetCookieHeaders(client)

        then:
        setCookies.keySet().containsAll(["OAUTH2_STATE", "OAUTH2_PKCE", "OPENID_NONCE"])
        setCookies.values().every { !it.toLowerCase().contains("samesite") }

        cleanup:
        server.close()
    }

    void "SameSite can be configured for the state, PKCE and nonce cookies"() {
        given:
        EmbeddedServer server = startServer([
                "micronaut.security.oauth2.state.cookie.cookie-same-site"       : "None",
                "micronaut.security.oauth2.state.cookie.cookie-secure"          : true,
                "micronaut.security.oauth2.pkce.cookie.cookie-same-site"        : "Strict",
                "micronaut.security.oauth2.openid.nonce.cookie.cookie-same-site": "Lax",
        ])
        BlockingHttpClient client = server.applicationContext.createBean(HttpClient, server.URL).toBlocking()

        expect:
        SameSite.None == server.applicationContext.getBean(CookieStatePersistenceConfiguration).cookieSameSite.get()
        SameSite.Strict == server.applicationContext.getBean(CookiePkcePersistenceConfiguration).cookieSameSite.get()
        SameSite.Lax == server.applicationContext.getBean(CookieNoncePersistenceConfiguration).cookieSameSite.get()

        when:
        Map<String, String> setCookies = loginSetCookieHeaders(client)

        then:
        setCookies["OAUTH2_STATE"].contains("SameSite=None")
        setCookies["OAUTH2_STATE"].contains("Secure")
        setCookies["OAUTH2_PKCE"].contains("SameSite=Strict")
        setCookies["OPENID_NONCE"].contains("SameSite=Lax")

        cleanup:
        server.close()
    }

    private EmbeddedServer startServer(Map<String, Object> extraConfiguration) {
        ApplicationContext.run(EmbeddedServer, [
                "spec.name"                                           : "OauthCookieSameSiteSpec",
                "micronaut.security.authentication"                   : "cookie",
                "micronaut.security.oauth2.pkce.persistence"          : "cookie",
                "micronaut.http.client.follow-redirects"              : false,
                "micronaut.security.oauth2.clients.auth.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
                "micronaut.security.oauth2.clients.auth.client-id"    : "xxx",
                "micronaut.security.oauth2.clients.auth.client-secret": "xxx",
        ] + extraConfiguration as Map<String, Object>)
    }

    private static Map<String, String> loginSetCookieHeaders(BlockingHttpClient client) {
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"))
        assert HttpStatus.FOUND == response.status()
        assert response.getHeaders().get(HttpHeaders.LOCATION).contains("/oauth2/default/v1/authorize")
        response.getHeaders().getAll(HttpHeaders.SET_COOKIE).collectEntries { String header ->
            [(header.substring(0, header.indexOf('='))): header]
        } as Map<String, String>
    }

    @Requires(property = "spec.name", value = "AuthServerOauthCookieSameSiteSpec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver

        AuthServerController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver
        }

        @Get("/oauth2/default/.well-known/openid-configuration")
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default","authorization_endpoint":"' + host + '/oauth2/default/v1/authorize","token_endpoint":"' + host + '/oauth2/default/v1/token","userinfo_endpoint":"' + host + '/oauth2/default/v1/userinfo","jwks_uri":"' + host + '/keys","response_types_supported":["code"],"response_modes_supported":["query","form_post"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"claims_supported":["iss","sub","aud","iat","exp","nonce"],"code_challenge_methods_supported":["S256"]}'
        }
    }
}
