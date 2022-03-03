package io.micronaut.security.denyall

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import jakarta.annotation.security.DenyAll

class JakartaDenyAllSpec extends DenyAllSpec {

    @Requires(env = Environment.TEST)
    @Requires(property = 'spec.name', value = "DenyAllSpec")
    @Replaces(DenyAllSpec.BookController.class)
    @Controller(DenyAllSpec.controllerPath)
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class BookController {

        @DenyAll
        @Get("/denied")
        String denied() {
            "You will not see this"
        }

        @Get("/index")
        String index() {
            "You will not see this"
        }

        @Secured(SecurityRule.DENY_ALL)
        @Get("/secureddenied")
        String securedDenyAll() {
            "You will not see this"
        }
    }
}
