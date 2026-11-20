package io.micronaut.security.docs.cspnonce

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import io.micronaut.views.ModelAndView
import jakarta.inject.Inject
import spock.lang.Specification

import java.util.regex.Matcher

@Property(name = "spec.name", value = "CspNonceViewModelProcessorTest")
@Property(name = "micronaut.security.csp.script-src.nonce", value = "true")
@MicronautTest
class CspNonceViewModelProcessorTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "the view renders the nonce of the response header"() {
        when:
        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-nonce"), String)
        Matcher matcher = response.body() =~ /<script nonce="([^"]+)">/

        then:
        matcher.find()
        response.header("Content-Security-Policy").contains("'nonce-" + matcher.group(1) + "'")
    }

    @Requires(property = "spec.name", value = "CspNonceViewModelProcessorTest")
    @Controller("/csp-nonce")
    static class CspNonceController {

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Get
        ModelAndView<Map<String, Object>> index() {
            new ModelAndView<>("csp-nonce", [title: "CSP nonce"] as Map<String, Object>)
        }
    }
}
