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
import io.micronaut.security.csp.ContentSecurityPolicy
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
@Property(name = "micronaut.security.csp.script-src.self", value = "true")
@MicronautTest
class ImagesContentSecurityPolicyGeneratorTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "the overridden directive replaces the configured one"() {
        when:
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-generator-images"), String)
        ContentSecurityPolicy policy = ContentSecurityPolicy.of(response)

        then:
        policy.imgSrc().toHeaderValue() == "img-src 'self' https://images.example.com"
        policy.scriptSrc().toHeaderValue() == "script-src 'self'"
    }

    @Requires(property = "spec.name", value = "ImagesContentSecurityPolicyGeneratorTest")
    @Controller("/csp-generator-images")
    static class ImagesController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            "ok"
        }
    }
}
