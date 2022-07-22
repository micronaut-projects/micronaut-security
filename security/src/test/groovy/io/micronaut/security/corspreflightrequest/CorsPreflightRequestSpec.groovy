package io.micronaut.security.corspreflightrequest

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Delete
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification

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

    @Requires(property = 'spec.name', value = 'CorsPreflightRequestSpec')
    @Controller("/register")
    static class RegisterController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Delete
        @Produces(MediaType.TEXT_PLAIN)
        String register() {
            "Hello"
        }
    }
}
