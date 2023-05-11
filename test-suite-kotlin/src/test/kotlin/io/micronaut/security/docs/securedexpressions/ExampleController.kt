package io.micronaut.security.docs.securedexpressions

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import java.security.Principal

@Requires(property = "spec.name", value = "docexpressions")
//tag::exampleControllerExpressions[]
@Controller("/authenticated")
class ExampleController {
    @Secured("#{ user?.attributes?.get('email') == 'sherlock@micronaut.example' }")
    @Produces(MediaType.TEXT_PLAIN)
    @Get("/email")
    fun authenticationByEmail(principal: Principal) = "${principal.name} is authenticated"
}
//end::exampleControllerExpressions[]
