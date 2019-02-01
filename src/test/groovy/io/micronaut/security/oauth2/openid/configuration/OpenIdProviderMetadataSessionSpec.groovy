package io.micronaut.security.oauth2.openid.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class OpenIdProviderMetadataSessionSpec extends Specification {
    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "A OpenIdProviderMetadataSession bean is loaded from a Okta remote openid-configuration endpoint"() {

        given:
        String openIdConfigurationJson = 'src/test/resources/okta-openid-configuration.json'
        String path = '/oauth2/default/.well-known/openid-configuration'
        int mockHttpServerPort = SocketUtils.findAvailableTcpPort()
        String mockHttpServerUrl = "http://localhost:${mockHttpServerPort}"
        Map<String, Object> mockHttpServerConf = [
                'spec.name': 'MockHttpServer',
                'micronaut.security.enabled': true,
                'micronaut.server.port': mockHttpServerPort,
                'openidconfigurationfile': openIdConfigurationJson,
                'opendiconfigurationpath': '/oauth2/default/.well-known'
        ]
        EmbeddedServer mockHttpServer = ApplicationContext.run(EmbeddedServer, mockHttpServerConf)

        and:
        String openIdConfigurationEndpoint = "${mockHttpServerUrl}${path}"
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint
        ], Environment.TEST)

        when:
        OpenIdProviderMetadataSession metadata = context.getBean(OpenIdProviderMetadataSession)

        then:
        noExceptionThrown()

        and:
        metadata.endSessionEndpoint == "https://dev-265911.oktapreview.com/oauth2/default/v1/logout"

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()

        and:
        context.close()
    }
}
