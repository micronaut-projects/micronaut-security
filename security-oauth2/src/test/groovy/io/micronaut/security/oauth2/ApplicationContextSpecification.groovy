package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import mock.OpenIdConfigurationController
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

abstract class ApplicationContextSpecification extends Specification {
    @Shared
    int mockOpenIdHttpServerPort = SocketUtils.findAvailableTcpPort()

    @Shared
    String mockOpenIdHttpServerUrl = "http://localhost:${mockOpenIdHttpServerPort}"

    @Shared
    Map<String, Object> openIdMockServerConf = [
            "spec.name": "mockopenidprovider",
            'micronaut.server.port': mockOpenIdHttpServerPort,
            'mockserver.url': mockOpenIdHttpServerUrl,
            'mockserver.path': mockServerPath,
            ] as Map<String, Object>

    String getMockServerPath() {
        ''
    }

    @AutoCleanup
    @Shared
    EmbeddedServer openIdMockEmbeddedServer = ApplicationContext.run(EmbeddedServer, openIdMockServerConf)

    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run(configuration)

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
}
