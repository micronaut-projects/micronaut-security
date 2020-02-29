package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.ConfigurationFixture
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class OpenIdClientFactorySpec extends Specification {

    @Shared
    int authServerPort = SocketUtils.findAvailableTcpPort()

    Map<String, Object> getAuthServerConfiguration() {
        [
                'micronaut.server.port': authServerPort,
                'spec.name':'AuthServerOpenIdClientFactorySpec'
        ] as Map<String, Object>
    }

    Map<String, Object> getConfiguration() {
        [
                'micronaut.security.token.jwt.bearer.enabled': true,
                'micronaut.security.token.jwt.cookie.enabled': true,
                'micronaut.security.oauth2.clients.okta.openid.issuer': "http://localhost:${authServerPort}/oauth2/default",
        ] as Map<String, Object>
    }

    @AutoCleanup
    @Shared
    EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, authServerConfiguration)

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    void "starting an app does not call eagerly .well-known/openid-configuration"() {
        when:
        OpenIdConfigurationController openIdConfigurationController = authServer.applicationContext.getBean(OpenIdConfigurationController)

        then:
        openIdConfigurationController.invocations == 0
    }

    @Requires(property = 'spec.name', value = 'AuthServerOpenIdClientFactorySpec')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class OpenIdConfigurationController {
        int invocations = 0

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            invocations++
            '{"issuer":"https://dev-133320.okta.com/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"https://dev-133320.okta.com/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }
}
