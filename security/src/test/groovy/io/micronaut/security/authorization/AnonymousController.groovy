
package io.micronaut.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.authentication.Authentication
import io.reactivex.Single

import javax.annotation.Nullable
import java.security.Principal

@Requires(property = 'spec.name', value = 'authorization')
@Controller('/anonymous')
class AnonymousController {

    @Get("/hello")
    String hello(@Nullable Principal principal) {
        "You are ${principal != null ? principal.getName() : 'anonymous'}"
    }
}
