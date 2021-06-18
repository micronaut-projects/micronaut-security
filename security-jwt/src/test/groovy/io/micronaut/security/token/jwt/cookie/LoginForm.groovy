package io.micronaut.security.token.jwt.cookie

import io.micronaut.core.annotation.Introspected

@Introspected
class LoginForm {
    String username
    String password
}
