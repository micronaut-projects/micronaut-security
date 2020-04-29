package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import mock.OpenIdConfigurationController
import spock.lang.AutoCleanup
import spock.lang.Retry
import spock.lang.Shared
import spock.lang.Specification

@Retry(mode = Retry.Mode.SETUP_FEATURE_CLEANUP)
abstract class ApplicationContextSpecification extends Specification {

    int mockOpenIdHttpServerPort
    String mockOpenIdHttpServerUrl
    Map<String, Object> openIdMockServerConf
    EmbeddedServer openIdMockEmbeddedServer
    ApplicationContext applicationContext

    String getMockServerPath() {
        ''
    }

    String getIssuer() {
        assert openIdMockEmbeddedServer.applicationContext.containsBean(OpenIdConfigurationController)
        assert mockOpenIdHttpServerUrl != null
        "${mockOpenIdHttpServerUrl}${mockServerPath}"
    }

    Map<String, Object> getConfiguration() {
        [
                'micronaut.security.token.jwt.bearer.enabled': false,
                'micronaut.security.token.jwt.cookie.enabled': true,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
                'micronaut.security.oauth2.clients.foo.openid.issuer': getIssuer(),
        ]
    }

    void setup() {
        mockOpenIdHttpServerPort = SocketUtils.findAvailableTcpPort()
        mockOpenIdHttpServerUrl = "http://localhost:${mockOpenIdHttpServerPort}"
        openIdMockServerConf = [
                "spec.name": "mockopenidprovider",
                'micronaut.server.port': mockOpenIdHttpServerPort,
                'mockserver.url': mockOpenIdHttpServerUrl,
                'mockserver.path': mockServerPath,
        ] as Map<String, Object>

        openIdMockEmbeddedServer = ApplicationContext.run(EmbeddedServer, openIdMockServerConf)
        applicationContext = ApplicationContext.run(configuration)
    }

    void cleanup() {
        applicationContext.close()
        openIdMockEmbeddedServer.close()
    }
}
