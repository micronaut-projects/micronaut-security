package io.micronaut.security.docs.passwordencoding

import io.micronaut.context.annotation.Requires
import io.micronaut.security.password.PasswordEncoder
import jakarta.inject.Singleton

import java.util.concurrent.ConcurrentHashMap

@Requires(property = "spec.name", value = "PasswordEncodingTest")
//tag::clazz[]
@Singleton
class UserStore {

    private final Map<String, String> encodedPasswords = new ConcurrentHashMap<>()
    private final PasswordEncoder passwordEncoder

    UserStore(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder
    }

    void register(String username, String rawPassword) {
        encodedPasswords.put(username, passwordEncoder.encode(rawPassword)) // <1>
    }

    String findEncodedPassword(String username) {
        encodedPasswords.get(username)
    }
}
//end::clazz[]
