package io.micronaut.security.utils.serverrequestcontextspec

import io.micronaut.context.ApplicationContext
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.*

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
        List<Message> messages = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/flux"), Argument.listOf(Message))

        then:
        messages

        when:
        Message message = messages[0]

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flux single result"() {
        when:
        Message message = httpClient.toBlocking().retrieve(HttpRequest.GET("/test/request-context/flux/singleresult"), Message)

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
