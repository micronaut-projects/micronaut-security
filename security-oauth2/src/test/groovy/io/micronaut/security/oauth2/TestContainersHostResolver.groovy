package io.micronaut.security.oauth2

import io.micronaut.context.BeanProvider
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.server.util.DefaultHttpHostResolver
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer

class TestContainersHostResolver implements HttpHostResolver {

    private final BeanProvider<EmbeddedServer> embeddedServer
    private final DefaultHttpHostResolver defaultHttpHostResolver

    TestContainersHostResolver(DefaultHttpHostResolver defaultHttpHostResolver,
                           @Nullable BeanProvider<EmbeddedServer> embeddedServer) {
        this.defaultHttpHostResolver = defaultHttpHostResolver
        this.embeddedServer = embeddedServer

    }

    @Override
    String resolve(@Nullable HttpRequest request) {

        if (isUsingTestContainers()) {
            return baseUrl
        }
        return defaultHttpHostResolver.resolve(request)
    }

    boolean isUsingTestContainers() {
        !System.getProperty("geb.env") || System.getProperty("geb.env").contains('docker')
    }

    String getProtocol() {
        'http'
    }

    String getHost() {
        isUsingTestContainers() ? "host.testcontainers.internal" : "localhost"
    }

    String getPort() {
        embeddedServer.get().port
    }

    String getBaseUrl() {
        "$protocol://$host:$port"
    }
}
