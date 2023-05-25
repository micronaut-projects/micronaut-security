package io.micronaut.security.docs.securedexpressions;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import java.security.Principal;

@Requires(property = "spec.name", value = "docexpressions")
//tag::exampleControllerExpressions[]
@Controller("/authenticated")
public class ExampleController {

    @Secured("#{ user?.attributes?.get('email') == 'sherlock@micronaut.example' }")
    @Produces(MediaType.TEXT_PLAIN)
    @Get("/email")
    public String authenticationByEmail(Principal principal) {
        return principal.getName() + " is authenticated";
    }
}
//end::exampleControllerExpressions[]
