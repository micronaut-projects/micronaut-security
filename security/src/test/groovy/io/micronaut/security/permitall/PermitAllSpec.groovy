package io.micronaut.security.permitall

import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.EmbeddedServerSpecification

import javax.annotation.security.PermitAll

class PermitAllSpec extends EmbeddedServerSpecification {
    static final String SPEC_NAME_PROPERTY = 'spec.name'

    public static final String controllerPath = '/permitall'

    @Override
    String getSpecName() {
        'PermitAllSpec'
    }

    void "PermitAllSpec collaborators are loaded"() {
        when:
        embeddedServer.applicationContext.getBean(BookController)

        then:
        noExceptionThrown()

        when:
        embeddedServer.applicationContext.getBean(LanguagesController)

        then:
        noExceptionThrown()
    }

    def "@PermitAll annotation is equivalent to @Secured('isAnonymous()')"() {
        when:
        client.exchange(HttpRequest.GET("${controllerPath}/books"))

        then:
        noExceptionThrown()
    }

    def "@PermitAll annotation at class level is inherited by methods"() {
        when:
        client.exchange(HttpRequest.GET("${controllerPath}/languages"))

        then:
        noExceptionThrown()
    }

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'PermitAllSpec')
    @Controller(PermitAllSpec.controllerPath)
    static class BookController {

        @PermitAll
        @Get("/books")
        Map<String, Object> list() {
            [books: ['Building Microservice', 'Release it']]
        }
    }

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'PermitAllSpec')
    @Controller(PermitAllSpec.controllerPath)
    @PermitAll
    static class LanguagesController {

        @Get("/languages")
        Map<String, Object> list() {
            [languages: ['Groovy', 'Java']]
        }
    }
}
