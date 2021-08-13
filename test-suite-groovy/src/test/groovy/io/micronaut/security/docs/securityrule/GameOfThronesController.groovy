package io.micronaut.security.docs.securityrule

import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

//tag::clazz[]
@Controller("/got")
class GameOfThronesController {

    @Secured(SecurityRule.IS_ANONYMOUS) // <1>
    @BodySecured // <2>
    @Post('/secret')
    @Produces(MediaType.TEXT_PLAIN)
    String secret(@Body Object body) {
        'John real name is Aegon'
    }
}
//end::clazz[]