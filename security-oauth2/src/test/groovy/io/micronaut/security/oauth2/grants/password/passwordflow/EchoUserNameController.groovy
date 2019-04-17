package io.micronaut.security.oauth2.grants.password.passwordflow

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

import java.security.Principal

@Requires(property = "spec.name", value="passwordFlow")
@Controller("/echo")
class EchoUserNameController {

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Produces(MediaType.TEXT_PLAIN)
    @Get
    String index(Principal principal) {
        principal.name
    }
}
