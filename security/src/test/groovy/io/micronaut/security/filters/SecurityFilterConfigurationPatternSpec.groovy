package io.micronaut.security.filters

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.Specification

class SecurityFilterConfigurationPatternSpec extends Specification {

    private static final String SPEC_NAME = 'SecurityFilterConfigurationPatternSpec'

    void "micronaut.security.filter.pattern populates SecurityFilterConfiguration and restricts the SecurityFilter"() {
        given:
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                        : SPEC_NAME,
                'micronaut.security.filter.pattern': '/secured/**',
        ])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        expect:
        '/secured/**' == server.applicationContext.getBean(SecurityFilterConfiguration).pattern

        when: 'a path outside the pattern is not processed by the security filter'
        String result = client.retrieve(HttpRequest.GET('/public').accept(MediaType.TEXT_PLAIN))

        then:
        'Public' == result

        when: 'a path matching the pattern is secured'
        client.retrieve(HttpRequest.GET('/secured').accept(MediaType.TEXT_PLAIN))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.UNAUTHORIZED == e.status

        cleanup:
        httpClient?.close()
        server?.close()
    }

    void "deprecated micronaut.security.filter.path populates SecurityFilterConfiguration but does not change the SecurityFilter pattern"() {
        given:
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
                'spec.name'                     : SPEC_NAME,
                'micronaut.security.filter.path': '/secured/**',
        ])
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()

        expect:
        '/secured/**' == server.applicationContext.getBean(SecurityFilterConfiguration).pattern

        when: 'the filter still matches every path because it reads micronaut.security.filter.pattern'
        client.retrieve(HttpRequest.GET('/public').accept(MediaType.TEXT_PLAIN))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.UNAUTHORIZED == e.status

        cleanup:
        httpClient?.close()
        server?.close()
    }

    void "SecurityFilterConfiguration pattern defaults to match all"() {
        given:
        ApplicationContext ctx = ApplicationContext.run(['spec.name': SPEC_NAME])

        expect:
        '/**' == ctx.getBean(SecurityFilterConfiguration).pattern

        cleanup:
        ctx.close()
    }

    @Requires(property = 'spec.name', value = 'SecurityFilterConfigurationPatternSpec')
    @Controller
    static class PatternController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get('/public')
        String publicEndpoint() {
            'Public'
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get('/secured')
        String securedEndpoint() {
            'Secured'
        }
    }
}
