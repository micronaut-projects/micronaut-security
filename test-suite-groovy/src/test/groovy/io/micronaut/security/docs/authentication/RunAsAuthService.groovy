package io.micronaut.security.docs.authentication

import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.context.SecurityContextHolder
import jakarta.annotation.security.RunAs
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "RunAsTest")
//tag::clazz[]
@RunAs('{"name":"aegon","attributes":{"family_name":"Targaryen","roles":["ROLE_KING"]}}')
@Singleton
class RunAsAuthService {
    Authentication changeAuth() {
        SecurityContextHolder.securityContext.authentication
    }
}
//end::clazz[]
