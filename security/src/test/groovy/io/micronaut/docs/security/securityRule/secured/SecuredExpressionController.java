package io.micronaut.docs.security.securityRule.secured;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;

@Requires(property = "spec.name", value = "SecuredExpressionSpec")
@Controller("/example")
@Secured("#{ principal == 'Dean' }")
//@Secured("#{ #authentication.attributes.email == 'john@gameothrones.com' }")
public class SecuredExpressionController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/authenticated")
    public String authenticated(Authentication authentication) {
        return authentication.getName() + " is authenticated";
    }
}
