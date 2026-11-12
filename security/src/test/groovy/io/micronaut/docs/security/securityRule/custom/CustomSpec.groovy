package io.micronaut.docs.security.securityRule.custom

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class CustomSpec extends Specification {

    @Shared
    Map<String, Object> config = [
            'spec.name': 'doccustom',
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>)

    @Shared
    @AutoCleanup
    HttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.getURL())

    void "verify you can access an endpoint annotated with @Authenticated with an authenticated user"() {
        when:
        client.toBlocking().exchange(HttpRequest.GET("/example/authenticated")
                .basicAuth("user", "password"))

        then:
        noExceptionThrown()
    }
}
