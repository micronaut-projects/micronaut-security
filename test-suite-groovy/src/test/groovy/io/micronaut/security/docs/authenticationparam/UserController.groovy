package io.micronaut.security.docs.authenticationparam

//tag::imports[]
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import org.jspecify.annotations.Nullable
//end::imports[]
import io.micronaut.context.annotation.Requires

@Requires(property = "spec.name", value = "AuthenticationParamTest")
//tag::clazz[]

@Controller("/user")
class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    Map<String, Object> myinfo(@Nullable Authentication authentication) {
        if (authentication == null) {
            return [isLoggedIn: false]
        }
        [isLoggedIn: true,
         username: authentication.name,
         roles: authentication.roles]
    }
}
//end::clazz[]
