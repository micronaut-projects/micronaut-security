package io.micronaut.security.docs.passwordencoding

import io.micronaut.context.annotation.Requires
import io.micronaut.security.password.PasswordEncoder
import jakarta.inject.Singleton
import java.util.concurrent.ConcurrentHashMap

@Requires(property = "spec.name", value = "PasswordEncodingTest")
//tag::clazz[]
@Singleton
class UserStore(private val passwordEncoder: PasswordEncoder) {

    private val encodedPasswords = ConcurrentHashMap<String, String>()

    fun register(username: String, rawPassword: String) {
        encodedPasswords[username] = passwordEncoder.encode(rawPassword) // <1>
    }

    fun findEncodedPassword(username: String): String? = encodedPasswords[username]
}
//end::clazz[]
