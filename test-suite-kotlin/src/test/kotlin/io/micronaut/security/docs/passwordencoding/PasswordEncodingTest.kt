package io.micronaut.security.docs.passwordencoding

import io.micronaut.context.annotation.Property
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

@Property(name = "spec.name", value = "PasswordEncodingTest")
@MicronautTest(startApplication = false)
class PasswordEncodingTest {

    @Inject
    lateinit var userStore: UserStore

    @Inject
    lateinit var authenticationProvider: PasswordAuthenticationProvider

    @Test
    fun authenticatesAgainstTheEncodedPassword() {
        userStore.register("sherlock", "elementary")

        Assertions.assertTrue(userStore.findEncodedPassword("sherlock")!!.startsWith("\$argon2id\$v=19\$"))
        Assertions.assertTrue(authenticationProvider.authenticate(null, UsernamePasswordCredentials("sherlock", "elementary")).isAuthenticated)
        Assertions.assertFalse(authenticationProvider.authenticate(null, UsernamePasswordCredentials("sherlock", "wrong")).isAuthenticated)
        Assertions.assertFalse(authenticationProvider.authenticate(null, UsernamePasswordCredentials("watson", "elementary")).isAuthenticated)
        Assertions.assertEquals(
            authenticationProvider.authenticate(null, UsernamePasswordCredentials("sherlock", "wrong")).message,
            authenticationProvider.authenticate(null, UsernamePasswordCredentials("watson", "elementary")).message
        )
    }
}
