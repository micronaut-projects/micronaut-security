package io.micronaut.security.docs.cspgenerator

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
@MicronautTest
class ApplicationContentSecurityPolicyGeneratorTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "the custom generator defines the response header"() {
        when:
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator"), String)

        then:
        response.header("Content-Security-Policy") == "default-src 'self'; object-src 'none'"
    }

    @Requires(property = "spec.name", value = "ApplicationContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator")
    static class CspGeneratorController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            "ok"
        }
    }
}
