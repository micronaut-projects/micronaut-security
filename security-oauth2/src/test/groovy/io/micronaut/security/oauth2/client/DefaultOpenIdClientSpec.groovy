package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.CollectionUtils
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.uri.UriBuilder
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.Issue
import spock.lang.Specification

class DefaultOpenIdClientSpec extends Specification {

    @Issue("https://github.com/micronaut-projects/micronaut-security/issues/1199")
    void "DefaultOpenIdClient is created correctly"() {
        given:
        EmbeddedServer google = ApplicationContext.run(EmbeddedServer, ["spec.name": "DefaultOpenIdClientSpecGoogle"])
        EmbeddedServer cognito = ApplicationContext.run(EmbeddedServer, ["spec.name": "DefaultOpenIdClientSpecCognito"])
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, CollectionUtils.mapOf("spec.name", "DefaultOpenIdClientSpec",
                'micronaut.http.client.follow-redirects', StringUtils.FALSE,
                'micronaut.security.authentication', 'idtoken',
                'micronaut.security.redirect.unauthorized.url', '/oauth/login/cognito',
                'micronaut.security.oauth2.clients.google.client-id', 'xxx',
                'micronaut.security.oauth2.clients.google.client-secret', 'yyyy',
                'micronaut.security.oauth2.clients.google.openid.issuer', "http://localhost:${google.port}/oauth2/default",
                'micronaut.security.oauth2.clients.cognito.client-id', 'xxx',
                'micronaut.security.oauth2.clients.cognito.client-secret', 'yyyy',
                'micronaut.security.oauth2.clients.cognito.openid.issuer', "http://localhost:${cognito.port}/oauth2/default"))

        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        URI uri = UriBuilder.of("/oauth").path("login").path("cognito").build()
        HttpRequest<?> request = HttpRequest.GET(uri)

        when:
        client.exchange(request)

        then:
        noExceptionThrown()

        cleanup:
        client.close()
        httpClient.close()
        server.close()
        cognito.close()
        google.close()
    }

    @Requires(property = 'spec.name', value = 'DefaultOpenIdClientSpecGoogle')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class GoogleOpenIdConfigurationController {
        int invocations = 0

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            invocations++
            '{"issuer":"https://dev-133320.okta.com/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"https://dev-133320.okta.com/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }

    @Requires(property = 'spec.name', value = 'DefaultOpenIdClientSpecCognito')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class CognitoOpenIdConfigurationController {
        int invocations = 0

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            invocations++
            '{"issuer":"https://dev-133320.okta.com/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"https://dev-133320.okta.com/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }
}
