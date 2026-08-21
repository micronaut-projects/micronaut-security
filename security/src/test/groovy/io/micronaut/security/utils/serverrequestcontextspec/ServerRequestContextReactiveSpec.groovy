package io.micronaut.security.utils.serverrequestcontextspec

import io.micronaut.context.ApplicationContext
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.BlockingHttpClient
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
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        expect:
        embeddedServer.applicationContext.containsBean(MyController)

        when:

        Message message = client.retrieve(HttpRequest.GET("/test/request-context/simple"), Message)

        then:
        message
        message.message == 'Sergio'

        when:
        message = client.retrieve(HttpRequest.GET("/test/request-context"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flowable with subscribe on"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = client.retrieve(HttpRequest.GET("/test/request-context/flowable-subscribeon"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flowable callable"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = client.retrieve(HttpRequest.GET("/test/request-context/flowable-callable"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flux"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        List<Message> messages = client.retrieve(HttpRequest.GET("/test/request-context/flux"), Argument.listOf(Message))

        then:
        messages

        when:
        Message message = messages[0]

        then:
        message
        message.message == 'Sergio'
    }

    def "verify flux single result"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = client.retrieve(HttpRequest.GET("/test/request-context/flux/singleresult"), Message)

        then:
        message
        message.message == 'Sergio'
    }

    @Ignore
    def "verify flux subscribe on"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        Message message = client.retrieve(HttpRequest.GET("/test/request-context/flux-subscribeon"), Message)

        then:
        message
        message.message == 'Sergio'
    }
}
