package io.micronaut.security.docs.passwordencoding;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "PasswordEncodingTest")
@MicronautTest(startApplication = false)
class PasswordEncodingTest {

    @Inject
    UserStore userStore;

    @Inject
    PasswordAuthenticationProvider<Object> authenticationProvider;

    @Test
    void authenticatesAgainstTheEncodedPassword() {
        userStore.register("sherlock", "elementary");

        assertTrue(userStore.findEncodedPassword("sherlock").orElseThrow().startsWith("$argon2id$v=19$"));
        assertTrue(authenticationProvider.authenticate(null, new UsernamePasswordCredentials("sherlock", "elementary")).isAuthenticated());
        assertFalse(authenticationProvider.authenticate(null, new UsernamePasswordCredentials("sherlock", "wrong")).isAuthenticated());
        assertFalse(authenticationProvider.authenticate(null, new UsernamePasswordCredentials("watson", "elementary")).isAuthenticated());
    }
}
