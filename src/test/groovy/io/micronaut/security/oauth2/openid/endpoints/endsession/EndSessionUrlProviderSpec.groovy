package io.micronaut.security.oauth2.openid.endpoints.endsession

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.configuration.OauthConfiguration
import io.micronaut.security.oauth2.openid.configuration.FileOpenIdConfigurationController
import io.micronaut.security.oauth2.openid.endpoints.OpenIdEndpoints
import io.micronaut.security.token.reader.TokenResolver
import spock.lang.Specification

class EndSessionUrlProviderSpec extends Specification {

    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "If beans (TokenResolver, OpenIdEndpoints, OauthConfiguration, EndSessionEndpointConfiguration) are present then a EndSessionUrlProvider is loaded"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/okta-openid-configuration.json'
        String controllerPath = '/oauth2/default'
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
        String issuer = "${mockHttpServerUrl}${controllerPath}"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.client-id'           : 'XXX',
                'micronaut.security.oauth2.issuer': issuer
        ], Environment.TEST)

        when:
        context.getBean(TokenResolver)

        then:
        noExceptionThrown()

        when:
        context.getBean(OpenIdEndpoints)

        then:
        noExceptionThrown()

        when:
        context.getBean(OauthConfiguration)

        then:
        noExceptionThrown()

        when:
        context.getBean(EndSessionEndpointConfiguration)

        then:
        noExceptionThrown()

        when:
        context.getBean(EndSessionUrlProvider)

        then:
        noExceptionThrown()

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()
        context.close()
    }
}
