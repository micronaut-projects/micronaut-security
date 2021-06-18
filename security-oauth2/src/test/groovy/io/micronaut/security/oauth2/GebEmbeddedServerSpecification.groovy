package io.micronaut.security.oauth2

import geb.Browser
import geb.spock.GebSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.testcontainers.Testcontainers
import spock.lang.AutoCleanup
import spock.lang.Shared

abstract class GebEmbeddedServerSpecification extends GebSpec implements ConfigurationFixture {

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = embeddedServer.applicationContext

    @Shared
    @AutoCleanup
    HttpClient httpClient = applicationContext.createBean(HttpClient, embeddedServer.getURL())

    @Shared
    BlockingHttpClient client = httpClient.toBlocking()


    @Override
    Browser getBrowser() {
        Browser b = super.getBrowser()
        if (embeddedServer && !b.baseUrl) {
            b.baseUrl = baseUrl
        }
        b
    }

    String getProtocol() {
        'http'
    }

    String getHost() {
        isUsingTestContainers() ? "host.testcontainers.internal" : "localhost"
    }

    String getPort() {
        if (isUsingTestContainers()) {
            Testcontainers.exposeHostPorts(embeddedServer.port)
        }
        embeddedServer.port
    }

    String getBaseUrl() {
        "$protocol://$host:$port"
    }
}
