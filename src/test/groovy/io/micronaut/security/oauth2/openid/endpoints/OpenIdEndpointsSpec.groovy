package io.micronaut.security.oauth2.openid.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.oauth2.openid.configuration.FileOpenIdConfigurationController
import spock.lang.Specification

class OpenIdEndpointsSpec extends Specification {

    private static final String SPEC_NAME_PROPERTY = 'spec.name'

    void "OpenIdEndpoints is loaded"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/okta-openid-configuration.json'

        String controllerPath = '/oauth2/default/.well-known'
        String path = "${controllerPath}/openid-configuration"
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
        String openIdConfigurationEndpoint = "${mockHttpServerUrl}${path}"

        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
                'micronaut.security.enabled'                    : true,
                'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint
        ], Environment.TEST)

        when:
        context.getBean(OpenIdEndpoints)

        then:
        noExceptionThrown()

        and:
        mockHttpServer.applicationContext.getBean(FileOpenIdConfigurationController).called == 1

        cleanup:
        mockHttpServer.close()

        and:
        context.close()
    }
}
