package io.micronaut.security.oauth2.endpoint.authorization.pkce

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.handlers.RedirectingLoginHandler
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.PendingFeature
import spock.lang.Shared
import spock.lang.Specification

class PkceSessionSpec extends Specification {

    @Shared
    @AutoCleanup
    EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerPkceSessionSpec",
            "micronaut.security.oauth2.pkce.enabled": StringUtils.TRUE,
            // Enable so that beans in this package (such as the beans in this test) io.micronaut.security.oauth2.endpoint.authorization.pkce are loaded

    ] as Map<String, Object>)

    @Shared
    @AutoCleanup
    EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "PkceSessionSpec",
            "micronaut.security.authentication": "session",
            "micronaut.security.oauth2.pkce.enabled": StringUtils.TRUE,
            "micronaut.security.oauth2.pkce.persistence": "session",
            "micronaut.security.oauth2.clients.authserver.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
            "micronaut.security.oauth2.clients.authserver.client-id": "xxx",
            "micronaut.security.oauth2.clients.authserver.client-secret": "xxx",
            "micronaut.security.redirect.unauthorized.url": "/oauth/login/authserver",
    ])

    @PendingFeature
    void "test PKCE with session persistence"() {
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
        HttpRequest<?> request = HttpRequest.GET("/").accept(MediaType.TEXT_HTML_TYPE)
        HttpResponse<?> response = client.exchange(request)

        then:
        HttpStatus.SEE_OTHER == response.status()
    }

    @Requires(property = "spec.name", value="PkceSessionSpec")
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Status(HttpStatus.I_AM_A_TEAPOT)
        void index() {
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceSessionSpec")
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        AuthServerController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver
        }
        @Consumes(MediaType.TEXT_HTML)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/oauth2/default/v1/authorize")
        @Status(HttpStatus.OK)
        void authorized() {
            String foo = "";
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/oauth2/default/.well-known/openid-configuration")
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default","authorization_endpoint":"' + host + '/oauth2/default/v1/authorize","token_endpoint":"' + host + '/oauth2/default/v1/token","userinfo_endpoint":"' + host + '/oauth2/default/v1/userinfo","registration_endpoint":"' + host + '/oauth2/v1/clients","jwks_uri":"' + host + '/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"' + host + '/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"' + host + '/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"' + host + '/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }
}
