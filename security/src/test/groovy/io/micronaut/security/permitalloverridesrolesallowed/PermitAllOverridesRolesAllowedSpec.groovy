package io.micronaut.security.permitalloverridesrolesallowed

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.testutils.EmbeddedServerSpecification

import javax.annotation.security.PermitAll
import javax.annotation.security.RolesAllowed

class PermitAllOverridesRolesAllowedSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'PermitAllOverridesRolesAllowedSpec'
    }

    void "PermitAllOverridesRolesAllowedSpec collaborators are loaded"() {
        when:
        applicationContext.getBean(BookController)

        then:
        noExceptionThrown()
    }

    def " If the RolesAllowed is specified at the class level and PermitAll annotation is applied at the method level, the PermitAll annotation overrides the RolesAllowed for the specified method."() {
        when:
        client.exchange(HttpRequest.GET("/permitalloverridesrolesallowed/books"))

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'PermitAllOverridesRolesAllowedSpec')
    @Controller('/permitalloverridesrolesallowed')
    @RolesAllowed(['ROLE_ADMIN'])
    static class BookController {
        @PermitAll
        @Get("/books")
        Map<String, Object> list() {
            [books: ['Building Microservice', 'Release it']]
        }
    }
}
