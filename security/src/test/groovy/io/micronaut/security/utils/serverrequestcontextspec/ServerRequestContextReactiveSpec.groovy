package io.micronaut.security.utils.serverrequestcontextspec

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.AutoCleanup
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise

@Stepwise
class ServerRequestContextReactiveSpec extends Specification {

    @Shared @AutoCleanup EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name': 'ServerRequestContextReactiveSpec',
            ])

    @Shared
    @AutoCleanup
    HttpClient httpClient =
            embeddedServer.getApplicationContext().createBean(HttpClient.class, embeddedServer.URL)

    def "verifies ServerRequestContext.currentRequest() does not return null for reactive flows"() {
        expect:
        embeddedServer.applicationContext.containsBean(MyController)

        when:

        Message message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/simple"), Message)

        then:
        message
        message.message == 'Sergio'

        when:
        message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flowable with subscribe on"() {
        when:
        Message message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/flowable-subscribeon"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flowable callable"() {
        when:
        Message message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/flowable-callable"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flux"() {
        when:
        Message message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/flux"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    @Ignore
    def "verify flux subscribe on"() {
        when:
        Message message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/flux-subscribeon"), Message)

        then:
        message
        message.message == 'Sergio'
    }
}
