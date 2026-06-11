package io.micronaut.security.docs.authentication

import io.micronaut.context.annotation.Requires
import io.micronaut.security.annotation.RunAsUser
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.context.SecurityContextHolder
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "RunAsUserTest")
//tag::clazz[]
@RunAsUser(name = "aegon", roles = ["ROLE_KING"])
@Singleton
class RunAsUserService {
    Authentication changeAuth() {
        SecurityContextHolder.securityContext.authentication
    }
}
//end::clazz[]
