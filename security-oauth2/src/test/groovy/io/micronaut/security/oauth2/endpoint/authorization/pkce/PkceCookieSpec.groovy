package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.CollectionUtils
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.handlers.RedirectingLoginHandler
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.BrowserHttpRequest
import spock.lang.Specification

class PkceCookieSpec extends Specification {
    void "test PKCE with cookie persistence"() {
        EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerPkceCookieSpec",
            "micronaut.security.oauth2.pkce.enabled": StringUtils.TRUE,
            // Enable so that beans in this package (such as the beans in this test) io.micronaut.security.oauth2.endpoint.authorization.pkce are loaded
        ] as Map<String, Object>)

        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "PkceCookieSpec",
            "micronaut.security.authentication": "cookie",
            "micronaut.security.oauth2.pkce.persistence": "cookie",
            "micronaut.security.oauth2.pkce.enabled": StringUtils.TRUE,
            "micronaut.security.oauth2.clients.auth.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
            "micronaut.security.oauth2.clients.auth.client-id": "xxx",
            "micronaut.security.oauth2.clients.auth.client-secret": "xxx",
            "micronaut.security.redirect.unauthorized.url": "/oauth/login/auth",
        ])
        expect:
        server
        server.applicationContext.containsBean(HomeController)
        server.applicationContext.containsBean(RedirectingLoginHandler)
        server.applicationContext.containsBean(OauthClient)

        and:
        oauthServer
        oauthServer.applicationContext.containsBean(AuthServerController)
        when:
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        HttpRequest<?> request = BrowserHttpRequest.GET("/secured")
        HttpResponse<?> response = client.exchange(request)

        then:
        HttpStatus.OK == response.status()
        oauthServer.applicationContext.getBean(AuthServerController).codeChallenge
        'S256' == oauthServer.applicationContext.getBean(AuthServerController).codeChallengeMethod
        oauthServer.applicationContext.getBean(AuthServerController).state
        when:
        HttpRequest<?> callbackRequest = HttpRequest.POST("/oauth/callback/auth",
                CollectionUtils.mapOf("code", "xxx",
                        "state", oauthServer.applicationContext.getBean(AuthServerController).state ))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        response = client.exchange(callbackRequest)

        then:
        HttpStatus.OK == response.status()

        cleanup:
        server.close()
        oauthServer.close()
    }

    @Requires(property = "spec.name", value="PkceCookieSpec")
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Status(HttpStatus.I_AM_A_TEAPOT)
        void index() {
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Status(HttpStatus.ENHANCE_YOUR_CALM)
        @Get("/secured")
        void secured() {
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceCookieSpec")
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        String codeChallenge
        String codeChallengeMethod
        String state
        String codeVerifier
        AuthServerController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver
        }
        @Consumes(MediaType.TEXT_HTML)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/oauth2/default/v1/authorize")
        @Status(HttpStatus.OK)
        void authorized(HttpRequest<?> request) {
            codeChallenge = request.getParameters().get("code_challenge")
            codeChallengeMethod = request.getParameters().get("code_challenge_method")
            state = request.getParameters().get("state")
        }

        @Post("/oauth2/default/v1/token")
        @Status(HttpStatus.OK)
        void token(HttpRequest<?> request) {
            codeVerifier = request.getParameters().get("code_verifier")
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/oauth2/default/.well-known/openid-configuration")
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default","authorization_endpoint":"' + host + '/oauth2/default/v1/authorize","token_endpoint":"' + host + '/oauth2/default/v1/token","userinfo_endpoint":"' + host + '/oauth2/default/v1/userinfo","registration_endpoint":"' + host + '/oauth2/v1/clients","jwks_uri":"' + host + '/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"' + host + '/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"' + host + '/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"' + host + '/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }
}
