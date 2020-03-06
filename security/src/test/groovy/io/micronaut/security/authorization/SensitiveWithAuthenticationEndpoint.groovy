package io.micronaut.security.authorization

import io.micronaut.context.annotation.Requires
import io.micronaut.management.endpoint.annotation.Endpoint
import io.micronaut.management.endpoint.annotation.Read
import io.micronaut.security.authentication.Authentication

@Requires(property = 'spec.name', value = 'authorization')
@Endpoint(id = "sensitiveauthentication", defaultSensitive = true)
class SensitiveWithAuthenticationEndpoint {

    @Read
    String hello(Authentication authentication) {
        "Hello ${authentication.name}"
    }
}
