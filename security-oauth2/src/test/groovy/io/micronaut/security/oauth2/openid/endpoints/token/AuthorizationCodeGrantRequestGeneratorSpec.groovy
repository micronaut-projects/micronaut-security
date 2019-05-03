package io.micronaut.security.oauth2.openid.endpoints.token

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.endpoints.token.request.TokenEndpointClient
import io.micronaut.security.oauth2.openid.configuration.FileOpenIdConfigurationController
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata
import spock.lang.Specification

class AuthorizationCodeGrantRequestGeneratorSpec extends Specification {

    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "A bean AuthorizationCodeGrantRequestGenerator is loaded"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/aws-cognito-openid-configuration.json'
        String poolId = '/eu-west-1_ZLiEFD4b6/'
        String controllerPath = "${poolId}"
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'MockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'openidconfigurationfile': openIdConfigurationJson,
                'opendiconfigurationpath': controllerPath
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        String issuer = "${mockHttpServerUrl}${poolId}"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.client-id'           : 'XXXX',
                'micronaut.security.oauth2.client-secret'       : 'YYYY',
                'micronaut.security.oauth2.openid.issuer': issuer,
                'micronaut.security.oauth2.token.redirect-uri'  : 'http://localhost:8080'
        ], Environment.TEST)

        when:
        context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        when:
        context.getBean(TokenEndpoint)

        then:
        noExceptionThrown()

        when:
        context.getBean(OauthClientConfiguration.class)

        then:
        noExceptionThrown()

        when:
        context.getBean(TokenEndpointClient)

        then:
        noExceptionThrown()

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }
}
