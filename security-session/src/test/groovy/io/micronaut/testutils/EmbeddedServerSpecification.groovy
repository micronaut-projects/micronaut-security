package io.micronaut.testutils

import io.micronaut.context.ApplicationContext
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

abstract class EmbeddedServerSpecification extends Specification implements ConfigurationFixture {

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
}
