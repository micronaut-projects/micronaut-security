package io.micronaut.security.authentication;

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class UsernamePasswordCredentialsValidationTest {
    @Test
    void usernameAndPasswordAreOptional(Validator validator) {
        assertTrue(validator.validate(new UsernamePasswordCredentials("foo", "bar")).isEmpty());
        // not blank
        assertFalse(validator.validate(new UsernamePasswordCredentials(null, null)).isEmpty());
        assertFalse(validator.validate(new UsernamePasswordCredentials("foo", null)).isEmpty());
        assertFalse(validator.validate(new UsernamePasswordCredentials("foo", "")).isEmpty());
        assertFalse(validator.validate(new UsernamePasswordCredentials(null, "bar")).isEmpty());
        assertFalse(validator.validate(new UsernamePasswordCredentials("", "bar")).isEmpty());
    }
}
