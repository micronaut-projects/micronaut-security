package io.micronaut.security.docs.securityrule.secured

//tag::exampleControllerPlusImports[]
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
//end::exampleControllerPlusImports[]
import io.micronaut.context.annotation.Requires

@Requires(property = "spec.name", value = "SecuredTest")
//tag::exampleControllerPlusImports[]

@Controller("/example")
@Secured(SecurityRule.IS_AUTHENTICATED) // <1>
class ExampleController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/admin")
    @Secured("ROLE_ADMIN", "ROLE_X") // <2>
    fun withroles(): String = "You have ROLE_ADMIN or ROLE_X roles"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/anonymous")
    @Secured(SecurityRule.IS_ANONYMOUS)  // <3>
    fun anonymous(): String = "You are anonymous"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/authenticated") // <1>
    fun authenticated(authentication: Authentication): String = "${authentication.name} is authenticated"
}
//end::exampleControllerPlusImports[]
