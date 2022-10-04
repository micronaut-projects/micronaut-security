package io.micronaut.security.oauth2.client

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.ConfigurationFixture
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class OpenIdClientFactorySpec extends Specification implements ConfigurationFixture {

    @Shared
    int authServerPort = SocketUtils.findAvailableTcpPort()

    Map<String, Object> getAuthServerConfiguration() {
        [
                'micronaut.server.port': authServerPort,
                'spec.name'            : 'AuthServerOpenIdClientFactorySpec'
        ] as Map<String, Object>
    }

    @Shared
    Map<String, Object> defaultServerConfiguration =
            configuration + [
                    'micronaut.security.authentication'                       : 'cookie',
                    'micronaut.security.oauth2.clients.okta.openid.issuer'    : "http://localhost:${authServerPort}/oauth2/default",
                    'micronaut.security.oauth2.clients.keycloak.openid.issuer': "http://localhost:${authServerPort}/oauth2/additional",
            ] as Map<String, Object>

    @AutoCleanup
    @Shared
    EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, authServerConfiguration)

    void "starting an app does not call eagerly .well-known/openid-configuration by default"() {
        given:
        EmbeddedServer testServer = ApplicationContext.run(EmbeddedServer, defaultServerConfiguration)

        when:
        OpenIdConfigurationController openIdConfigurationController = authServer.applicationContext.getBean(OpenIdConfigurationController)

        then:
        openIdConfigurationController.defaultIssuerInvocations == 0
        openIdConfigurationController.additionalIssuerInvocations == 0

        cleanup:
        testServer.close()
    }

    void "starting an app does not call eagerly .well-known/openid-configuration if eager-provider-init is false"() {
        given:
        EmbeddedServer testServer = ApplicationContext.run(EmbeddedServer, defaultServerConfiguration + [
                'micronaut.security.oauth2.openid.eager-provider-init': 'false',
        ])

        when:
        OpenIdConfigurationController openIdConfigurationController = authServer.applicationContext.getBean(OpenIdConfigurationController)

        then:
        openIdConfigurationController.defaultIssuerInvocations == 0
        openIdConfigurationController.additionalIssuerInvocations == 0

        cleanup:
        testServer.close()
    }

    void "starting an app calls .well-known/openid-configuration eagerly if eager-provider-init is true"() {
        given:
        EmbeddedServer testServer = ApplicationContext.run(EmbeddedServer, defaultServerConfiguration + [
                'micronaut.security.oauth2.openid.eager-provider-init': 'true',
        ])

        when:
        OpenIdConfigurationController openIdConfigurationController = authServer.applicationContext.getBean(OpenIdConfigurationController)

        then:
        openIdConfigurationController.defaultIssuerInvocations == 1
        openIdConfigurationController.additionalIssuerInvocations == 1

        cleanup:
        testServer.close()
    }

    @Requires(property = 'spec.name', value = 'AuthServerOpenIdClientFactorySpec')
    @Controller("/oauth2")
    static class OpenIdConfigurationController {
        int defaultIssuerInvocations = 0
        int additionalIssuerInvocations = 0
        String mockAuthServerResponse = '{"issuer":"https://dev-133320.okta.com/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"https://dev-133320.okta.com/oauth2/default/v1/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/default/.well-known/openid-configuration")
        String issuerRoute1() {
            defaultIssuerInvocations++
            mockAuthServerResponse
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/additional/.well-known/openid-configuration")
        String issuerRoute2() {
            additionalIssuerInvocations++
            mockAuthServerResponse
        }
    }
}
