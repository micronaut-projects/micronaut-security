package io.micronaut.docs.security.token.basicauth

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.testutils.YamlAsciidocTagCleaner
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.yaml.snakeyaml.Yaml
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class BasicAuthSpec extends Specification implements YamlAsciidocTagCleaner {


    @Shared
    Map<String, Object> config = [
            'spec.name' : 'docsbasicauth',
            'endpoints.beans.enabled'                 : true,
            'endpoints.beans.sensitive'               : true,
    ]

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, config as Map<String, Object>, Environment.TEST)

    @Shared
    @AutoCleanup
    RxHttpClient client = embeddedServer.applicationContext.createBean(RxHttpClient, embeddedServer.getURL())

    void "test /beans is secured but accesible if you supply valid credentials with Basic Auth"() {
        when:
        String token = 'dXNlcjpwYXNzd29yZA==' // user:passsword Base64
        client.toBlocking().exchange(HttpRequest.GET("/beans")
                .header("Authorization", "Basic ${token}".toString()), String)

        then:
        noExceptionThrown()
    }

    def "basicAuth() sets Authorization Header with Basic base64(username:password)"() {
        when:
        // tag::basicAuth[]
        HttpRequest request = HttpRequest.GET("/home").basicAuth('sherlock', 'password')
        // end::basicAuth[]

        then:
        request.headers.get('Authorization')
        request.headers.get('Authorization') == "Basic ${'sherlock:password'.bytes.encodeBase64().toString()}"
    }
}
