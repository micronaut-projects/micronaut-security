package io.micronaut.security.docs.authentication

import io.micronaut.context.annotation.Requires
import io.micronaut.security.annotation.Attribute
import io.micronaut.security.annotation.RunAs
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.context.SecurityContextHolder
import jakarta.inject.Singleton

@Requires(property = "spec.name", value = "RunAsTest")
//tag::clazz[]
@RunAs(
        name = "aegon",
        roles = ["TARGARYEN"],
        attributes = [
                @Attribute(key = "family_name", value = "Targaryen"),
                @Attribute(key = "given_name", value = "Aegon")
        ]
)
@Singleton
class RunAsService {
    Authentication changeAuth() {
        SecurityContextHolder.securityContext.authentication
    }
}
//end::clazz[]
