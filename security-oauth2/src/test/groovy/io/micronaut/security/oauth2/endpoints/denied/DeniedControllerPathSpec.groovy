package io.micronaut.security.oauth2.endpoints.denied

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import spock.lang.Specification

class DeniedControllerPathSpec extends Specification {

    void "DeniedController path defaults to /denied"() {
        given:
        Map<String, Object> conf = [
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.enabled': true,
        ]
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, conf)
        HttpClient httpClient = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET('/denied'), String)

        then:
        response.status() == HttpStatus.OK

        when:
        String html = response.body()

        then: 'Default description and title'
        html.contains('Sorry, you\'re not authorized to view this page')
        html.contains('<h1>Denied</h1>')
        html.contains('<title>Denied</title>')

        cleanup:
        httpClient.close()
        embeddedServer.close()
    }

    void "DeniedController path and copy can be changed"() {
        given:
        Map<String, Object> conf = [
                'micronaut.security.enabled': true,
                'micronaut.security.endpoints.denied.path': '/prohibido',
                'micronaut.security.endpoints.denied.description-copy': 'No estas autorizado para acceder a este recurso',
                'micronaut.security.endpoints.denied.title-copy': 'Prohibido',

                'micronaut.security.oauth2.enabled': true,
        ]
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, conf)
        HttpClient httpClient = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        client.exchange(HttpRequest.GET('/denied'))

        then:
        HttpClientResponseException e = thrown()
        e.response.status() == HttpStatus.UNAUTHORIZED

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET('/prohibido'), String)

        then:
        response.status() == HttpStatus.OK

        when:
        String html = response.body()

        then: 'changed default description and title'
        html.contains('No estas autorizado para acceder a este recurso')
        html.contains('<h1>Prohibido</h1>')
        html.contains('<title>Prohibido</title>')

        cleanup:
        httpClient.close()
        embeddedServer.close()
    }
}
