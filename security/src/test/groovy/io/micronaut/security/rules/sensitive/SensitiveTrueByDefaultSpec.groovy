package io.micronaut.security.rules.sensitive

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.EmbeddedServerSpecification

class SensitiveTrueByDefaultSpec extends EmbeddedServerSpecification {

    void "endpoints are sensitive: true by default"() {
        when:
        client.exchange(HttpRequest.GET("/defaultendpoint"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }
}
