
package io.micronaut.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.management.endpoint.annotation.Endpoint
import io.micronaut.management.endpoint.annotation.Read

import java.security.Principal

@Requires(property = 'spec.name', value = 'authorization')
@Endpoint(id = "sensitive", defaultSensitive = true)
class SensitiveEndpoint {

    @Read
    String hello(Principal principal) {
        "Hello ${principal.name}"
    }
}
