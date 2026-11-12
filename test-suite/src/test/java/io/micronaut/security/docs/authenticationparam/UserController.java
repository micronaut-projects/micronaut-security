package io.micronaut.security.docs.authenticationparam;

//tag::imports[]
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import org.jspecify.annotations.Nullable;

import java.util.Collections;
import java.util.Map;
//end::imports[]
import io.micronaut.context.annotation.Requires;

@Requires(property = "spec.name", value = "AuthenticationParamTest")
//tag::clazz[]

@Controller("/user")
public class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    public Map<String, Object> myinfo(@Nullable Authentication authentication) {
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
