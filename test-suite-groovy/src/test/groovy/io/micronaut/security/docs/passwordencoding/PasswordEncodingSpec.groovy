package io.micronaut.security.docs.passwordencoding

import io.micronaut.context.annotation.Property
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@Property(name = "spec.name", value = "PasswordEncodingTest")
@MicronautTest(startApplication = false)
class PasswordEncodingSpec extends Specification {

    @Inject
    UserStore userStore

    @Inject
    PasswordAuthenticationProvider<Object> authenticationProvider

    void "authenticates against the encoded password"() {
        when:
        userStore.register("sherlock", "elementary")

        then:
        userStore.findEncodedPassword("sherlock").orElseThrow().startsWith('$argon2id$v=19$')
        authenticationProvider.authenticate(null, new UsernamePasswordCredentials("sherlock", "elementary")).authenticated
        !authenticationProvider.authenticate(null, new UsernamePasswordCredentials("sherlock", "wrong")).authenticated
        !authenticationProvider.authenticate(null, new UsernamePasswordCredentials("watson", "elementary")).authenticated
    }
}
