package io.micronaut.security.docs.securityrule.permitall;

//tag::exampleControllerPlusImports[]
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
//end::exampleControllerPlusImports[]
import io.micronaut.context.annotation.Requires;

@Requires(property = "spec.name", value = "PermitAllTest")
//tag::exampleControllerPlusImports[]

@Controller("/example")
public class ExampleController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/admin")
    @RolesAllowed({"ROLE_ADMIN", "ROLE_X"}) // <1>
    public String withroles() {
        return "You have ROLE_ADMIN or ROLE_X roles";
    }

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/anonymous")
    @PermitAll  // <2>
    public String anonymous() {
        return "You are anonymous";
    }
}
//end::exampleControllerPlusImports[]
