package io.micronaut.docs.security.securityRule.custom;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.authentication.Authentication;

@Requires(property = "spec.name", value = "doccustom")
@Controller("/example")
class ExampleController {

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/authenticated") // <1>
    @Authenticated // <2>
    public String authenticated(Authentication authentication) {
        return authentication.getName() + " is authenticated";
    }
}
