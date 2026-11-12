package io.micronaut.security.docs.basicauth

import io.micronaut.http.HttpRequest
import spock.lang.Specification

class BasicAuthTest extends Specification {

    void "basicAuth() sets Authorization Header with Basic base64(username:password)"() {
        when:
        // tag::basicAuth[]
        HttpRequest request = HttpRequest.GET("/home").basicAuth('sherlock', 'password')
        // end::basicAuth[]

        then:
        request.headers.get('Authorization') == "Basic ${'sherlock:password'.bytes.encodeBase64().toString()}"
    }
}
