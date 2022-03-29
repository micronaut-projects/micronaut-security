package io.micronaut.security.filters


import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification

class SecurityFilterPatternSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'SecurityFilterPatternSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.filter.pattern': '/hello/**',
        ]
    }

    void "it is possible to disable the SecurityFilter with micronaut.security.filter.enabled = false"() {
        expect:
        applicationContext.containsBean(SecurityFilter.class)

        when:
        String result = client.retrieve(HttpRequest.GET('/goodbye').accept(MediaType.TEXT_PLAIN))

        then:
        noExceptionThrown()
        'Goodbye' == result

        when:
        client.retrieve(HttpRequest.GET('/hello').accept(MediaType.TEXT_PLAIN))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.UNAUTHORIZED == e.status

        when:
        client.retrieve(HttpRequest.GET('/hello/world').accept(MediaType.TEXT_PLAIN))

        then:
        e = thrown()
        HttpStatus.UNAUTHORIZED == e.status
    }

    @Requires(property = 'spec.name', value = 'SecurityFilterPatternSpec')
    @Controller("/hello")
    static class HelloController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String hello() {
            'Hello'
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/world")
        String helloWorld() {
            'Hello World'
        }
    }

    @Requires(property = 'spec.name', value = 'SecurityFilterPatternSpec')
    @Controller("/goodbye")
    static class GoodByeController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String goodbye() {
            'Goodbye'
        }
    }
}
