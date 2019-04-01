package io.micronaut.security.oauth2.openid.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class OpenIdProviderMetadataSpec extends Specification {
    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "A OpenIdProviderMetadata bean is loaded from a Auth0 remote openid-configuration endpoint"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/auth0-openid-configuration.json'
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'MockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'openidconfigurationfile': openIdConfigurationJson
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.issuer': mockHttpServerUrl
        ], Environment.TEST)

        when:
        OpenIdProviderMetadata metadata = context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        and:
        metadata.issuer == "https://micronautguides.eu.auth0.com/"

        and:
        metadata.authorizationEndpoint == "https://micronautguides.eu.auth0.com/authorize"

        and:
        metadata.tokenEndpoint == "https://micronautguides.eu.auth0.com/oauth/token"

        and:
        metadata.userinfoEndpoint == "https://micronautguides.eu.auth0.com/userinfo"

        and:
        metadata.jwksUri == "https://micronautguides.eu.auth0.com/.well-known/jwks.json"

        and:
        metadata.registrationEndpoint == "https://micronautguides.eu.auth0.com/oidc/register"

        and:
        metadata.revocationEndpoint == "https://micronautguides.eu.auth0.com/oauth/revoke"

        and:
        metadata.scopesSupported == ["openid","profile","offline_access","name","given_name","family_name","nickname","email","email_verified","picture","created_at","identities","phone","address"]

        and:
        metadata.responseTypesSupported == ["code","token","id_token","code token","code id_token","token id_token","code token id_token"]

        and:
        metadata.responseModesSupported == ["query","fragment","form_post"]

        and:
        metadata.subjectTypesSupported == ["public"]

        and:
        metadata.idTokenSigningAlgValuesSupported == ["HS256","RS256"]

        and:
        metadata.tokenEndpointAuthMethodsSupported == ["client_secret_basic","client_secret_post"]

        and:
        metadata.claimsSupported == ["aud","auth_time","created_at","email","email_verified","exp","family_name","given_name","iat","identities","iss","name","nickname","phone_number","picture","sub"]

        and:
        !metadata.requestUriParameterSupported

        //TODO "mfa_challenge_endpoint":"https://micronautguides.eu.auth0.com/mfa/challenge"}

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }

    void "A OpenIdProviderMetadata bean is loaded from a AWS Cognito remote openid-configuration endpoint"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/aws-cognito-openid-configuration.json'
        String poolId = '/eu-west-1_ZLiEFD4b6'
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'MockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'openidconfigurationfile': openIdConfigurationJson,
                'opendiconfigurationpath': "${poolId}"
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        String issuer = "${mockHttpServerUrl}${poolId}"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.issuer': issuer
        ], Environment.TEST)

        when:
        OpenIdProviderMetadata metadata = context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        and:
        metadata.authorizationEndpoint == "https://micronautguides.auth.eu-west-1.amazoncognito.com/oauth2/authorize"

        and:
        metadata.idTokenSigningAlgValuesSupported == ["RS256"]

        and:
        metadata.issuer == "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_ZLiEFD4b6"

        and:
        metadata.jwksUri == "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_ZLiEFD4b6/.well-known/jwks.json"

        and:
        metadata.responseTypesSupported == ["code","token","token id_token"]

        and:
        metadata.scopesSupported == ["openid","email","phone","profile"]

        and:
        metadata.subjectTypesSupported == ["public"]

        and:
        metadata.tokenEndpoint == "https://micronautguides.auth.eu-west-1.amazoncognito.com/oauth2/token"

        and:
        metadata.tokenEndpointAuthMethodsSupported == ["client_secret_basic","client_secret_post"]

        and:
        metadata.userinfoEndpoint == "https://micronautguides.auth.eu-west-1.amazoncognito.com/oauth2/userInfo"

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }

    void "A OpenIdProviderMetadata bean is loaded from a Okta remote openid-configuration endpoint"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/okta-openid-configuration.json'
        String path = '/oauth2/default'
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'MockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'openidconfigurationfile': openIdConfigurationJson,
                'opendiconfigurationpath': path
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        String issuer = "${mockHttpServerUrl}${path}"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.issuer': issuer
        ], Environment.TEST)

        when:
        OpenIdProviderMetadata metadata = context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        and:
        metadata.issuer == "https://dev-265911.oktapreview.com/oauth2/default"

        and:
        metadata.authorizationEndpoint == "https://dev-265911.oktapreview.com/oauth2/default/v1/authorize"

        and:
        metadata.tokenEndpoint == "https://dev-265911.oktapreview.com/oauth2/default/v1/token"

        and:
        metadata.userinfoEndpoint == "https://dev-265911.oktapreview.com/oauth2/default/v1/userinfo"

        and:
        metadata.registrationEndpoint == "https://dev-265911.oktapreview.com/oauth2/v1/clients"

        and:
        metadata.jwksUri == "https://dev-265911.oktapreview.com/oauth2/default/v1/keys"

        and:
        metadata.responseTypesSupported == ["code","id_token","code id_token","code token","id_token token","code id_token token"]

        and:
        metadata.responseModesSupported == ["query","fragment","form_post","okta_post_message"]

        and:
        metadata.grantTypesSupported == ["authorization_code","implicit","refresh_token","password"]

        and:
        metadata.subjectTypesSupported == ["public"]

        and:
        metadata.idTokenSigningAlgValuesSupported == ["RS256"]

        and:
        metadata.scopesSupported == ["openid","profile","email","address","phone","offline_access"]

        and:
        metadata.tokenEndpointAuthMethodsSupported == ["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"]

        and:
        metadata.claimsSupported == ["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"]

        and:
        metadata.codeChallengeMethodsSupported == ["S256"]

        and:
        metadata.introspectionEndpoint == "https://dev-265911.oktapreview.com/oauth2/default/v1/introspect"

        and:
        metadata.introspectionEndpointAuthMethodsSupported == ["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"]

        and:
        metadata.revocationEndpoint == "https://dev-265911.oktapreview.com/oauth2/default/v1/revoke"

        and:
        metadata.revocationEndpointAuthMethodsSupported == ["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"]

        and:
        metadata.requestParameterSupported

        and:
        metadata.requestObjectSigningAlgValuesSupported == ["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }
}
