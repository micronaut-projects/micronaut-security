package io.micronaut.security.docs.customauthentication

import io.micronaut.security.authentication.Authentication
import io.micronaut.serde.annotation.Serdeable

@Serdeable
data class AuthenticationWithEmail(val username: String, val email: String?) {
    companion object {
        fun of(authentication: Authentication): AuthenticationWithEmail {
            val obj = authentication.getAttributes()["email"]
            val email = obj?.toString()
            return AuthenticationWithEmail(authentication.name, email)
        }
    }
}
