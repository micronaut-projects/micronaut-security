package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@Property(name = "spec.name", value = "AuthenticationMapperTest")
@MicronautTest(startApplication = false)
class AuthenticationMapperTest {

    // Successful UserInfo Response
    // https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
    private static final String JSON = """
{
   "foo": "bar",
   "sub": "248289761001",
   "name": "Jane Doe",
   "given_name": "Jane",
   "family_name": "Doe",
   "preferred_username": "j.doe",
   "email": "janedoe@example.com",
   "picture": "https://example.com/janedoe/me.jpg"
  }""";

    @Test
    void authenticationMapper(AuthenticationMapper authenticationMapper) {
        assertInstanceOf(CompositeAuthenticationMapper.class, authenticationMapper);
        Authentication authentication = authenticationMapper.of(JSON);
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

    @Requires(property = "spec.name", value = "AuthenticationMapperTest")
    @Singleton
    static class CustomAuthenticationMapper extends AbstractAuthenticationMapper {

        private final JsonMapper jsonMapper;
        protected CustomAuthenticationMapper(JsonMapper jsonMapper,
                                             RolesFinder rolesFinder) {
            super(rolesFinder);
            this.jsonMapper = jsonMapper;
        }

        @Override
        public @Nullable Authentication of(@NonNull String token) {
            try {
                Map<String, Object> attributes = jsonMapper.readValue(token, Argument.mapOf(String.class, Object.class));
                Claims claims = new MapClaims(attributes);
                return of(claims);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
