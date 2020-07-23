package io.micronaut.security.corspreflightrequest


import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.security.EmbeddedServerSpecification

class CorsPreflightRequestSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'CorsPreflightRequestSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.server.cors.enabled': true]
    }

    void "preflight requests are authorized"() {
        given:
        HttpRequest request = HttpRequest.OPTIONS("/register")
                .header("Access-Control-Request-Method", "DELETE")
                .header("Access-Control-Request-Headers", "origin, x-requested-with")
                .header("Origin", "https://foo.bar.org")

        when:
        HttpResponse rsp = client.exchange(request)

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK
    }
}
