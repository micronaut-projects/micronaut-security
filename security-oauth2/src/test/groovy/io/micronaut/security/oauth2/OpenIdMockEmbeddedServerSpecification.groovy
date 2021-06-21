package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.AutoCleanup
import spock.lang.Shared

abstract class OpenIdMockEmbeddedServerSpecification extends ApplicationContextSpecification {
    @Shared
    int mockOpenIdHttpServerPort = SocketUtils.findAvailableTcpPort()

    @Shared
    String mockOpenIdHttpServerUrl = "http://localhost:${mockOpenIdHttpServerPort}"

    @Shared
    Map<String, Object> openIdMockServerConf = configuration + [
            'micronaut.server.port': mockOpenIdHttpServerPort,
            'mockserver.url': mockOpenIdHttpServerUrl,
            'mockserver.path': mockServerPath,
    ]

    String getMockServerPath() {
        ''
    }

    @AutoCleanup
    @Shared
    EmbeddedServer openIdMockEmbeddedServer = ApplicationContext.run(EmbeddedServer, openIdMockServerConf)

    String getIssuer() {
        assert "${mockOpenIdHttpServerUrl}${mockServerPath}"
        "${mockOpenIdHttpServerUrl}${mockServerPath}"
    }
}
