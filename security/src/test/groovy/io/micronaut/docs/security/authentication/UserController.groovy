package io.micronaut.docs.security.authentication;

// Although this is a Groovy file this is written as close to Java as possible to embedded in the docs

//tag::imports[]
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.core.annotation.Nullable

//end::imports[]

@Requires(property = 'spec.name', value = 'authenticationparam')
//tag::clazz[]
@Controller("/user")
class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    Map myinfo(@Nullable Authentication authentication) {
        if (authentication == null) {
            return Collections.singletonMap("isLoggedIn", false);
        }
        return CollectionUtils.mapOf("isLoggedIn", true,
                "username", authentication.getName(),
                "roles", authentication.getRoles()
        );
    }
}
//end::clazz[]
