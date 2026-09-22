package io.micronaut.security.docs.securityrule.permitall

//tag::exampleControllerPlusImports[]
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import jakarta.annotation.security.PermitAll
import jakarta.annotation.security.RolesAllowed
//end::exampleControllerPlusImports[]
import io.micronaut.context.annotation.Requires

@Requires(property = "spec.name", value = "PermitAllTest")
//tag::exampleControllerPlusImports[]

@Controller("/example")
class ExampleController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/admin")
    @RolesAllowed("ROLE_ADMIN", "ROLE_X") // <1>
    fun withroles(): String = "You have ROLE_ADMIN or ROLE_X roles"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/anonymous")
    @PermitAll  // <2>
    fun anonymous(): String = "You are anonymous"
}
//end::exampleControllerPlusImports[]
