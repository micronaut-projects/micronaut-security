package io.micronaut.security.token.jwt.nimbus;

import io.micronaut.context.annotation.Property;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationMapper;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "spec.name", value = "NimbusAuthenticationMapperTest")
@MicronautTest(startApplication = false)
class NimbusAuthenticationMapperTest {
    @Test
    void authenticationMapper(TokenGenerator tokenGenerator,
                              AuthenticationMapper authenticationMapper) {
        Map<String, Object> expectedAttributes = Map.of("sub", "248289761001",
            "name", "Jane Doe",
            "given_name", "Jane",
            "family_name", "Doe",
            "preferred_username", "j.doe",
            "email", "janedoe@example.com",
            "picture", "https://example.com/janedoe/me.jpg");
        Map<String, Object> attributes = new HashMap<>(expectedAttributes);
        attributes.put("foo", "bar");
        final String token = tokenGenerator.generateToken(attributes).orElseThrow();
        Authentication authentication = authenticationMapper.of(token);
        Authentication expected = Authentication.build("248289761001",
            Collections.emptyList(),
            Map.of("sub", "248289761001",
                "name", "Jane Doe",
                "given_name", "Jane",
                "family_name", "Doe",
                "preferred_username", "j.doe",
                "email", "janedoe@example.com",
                "picture", "https://example.com/janedoe/me.jpg"));
        assertEquals(expected, authentication);
    }
}
