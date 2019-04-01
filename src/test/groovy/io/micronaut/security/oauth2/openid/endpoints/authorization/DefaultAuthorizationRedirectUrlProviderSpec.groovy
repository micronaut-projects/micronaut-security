package io.micronaut.security.oauth2.openid.endpoints.authorization

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.openid.configuration.FileOpenIdConfigurationController
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata
import spock.lang.Specification

class DefaultAuthorizationRedirectUrlProviderSpec extends Specification {

    private static final SPEC_NAME_PROPERTY = 'spec.name'

    void "AuthorizationRedirectUrlProvider build a url"() {
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
                'opendiconfigurationpath': poolId
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        String issuer = "${mockHttpServerUrl}${poolId}"
        ApplicationContext context = ApplicationContext.run([
            (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
            'micronaut.security.enabled'                    : true,
            'micronaut.security.oauth2.client-id'           : 'XXXX',
            'micronaut.security.oauth2.issuer': issuer
        ], Environment.TEST)

        when:
        context.getBean(AuthenticationRequestProvider)

        then:
        noExceptionThrown()

        when:
        context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        when:
        AuthorizationRedirectUrlProvider authorizationRedirectUrlProvider = context.getBean(AuthorizationRedirectUrlProvider)

        then:
        noExceptionThrown()

        and:
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().startsWith( "https://micronautguides.auth.eu-west-1.amazoncognito.com/oauth2/authorize")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("response_type=code")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("scope=openid")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("client_id=XXXX")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("response_mode=query")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("redirect_uri")

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }
}
