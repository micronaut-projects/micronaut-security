package io.micronaut.security.permitall

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get

import jakarta.annotation.security.PermitAll

class JakartaPermitAllSpec extends PermitAllSpec {

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = 'PermitAllSpec')
    @Replaces(PermitAllSpec.BookController.class)
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
    @Replaces(PermitAllSpec.LanguagesController.class)
    @Controller(PermitAllSpec.controllerPath)
    @PermitAll
    static class LanguagesController {

        @Get("/languages")
        Map<String, Object> list() {
            [languages: ['Groovy', 'Java']]
        }
    }
}
