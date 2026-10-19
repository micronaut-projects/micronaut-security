package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.supabase.auth.SignupRequest;
import io.micronaut.supabase.auth.Supabase;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link SupabaseAuthenticationProvider} against a real Supabase Auth (GoTrue) server.
 */
@Testcontainers(disabledWithoutDocker = true)
@Property(name = "micronaut.security.authentication", value = "cookie")
@MicronautTest(startApplication = false)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseAuthenticationProviderTest implements TestPropertyProvider {
    private static final String EMAIL = "provider-test@example.com";
    private static final String PASSWORD = "correct-horse-battery";

    @Inject
    SupabaseAuthClient client;

    @Inject
    SupabaseAuthenticationProvider<?> provider;

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Supabase.getProperties();
    }

    @BeforeAll
    void signUp() {
        client.signup(null, new SignupRequest(EMAIL, null, PASSWORD, null, null, null, null, null));
    }

    @Test
    void validCredentialsYieldAnAuthenticationCarryingTheSupabaseTokens() {
        AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials(EMAIL, PASSWORD));

        assertTrue(response.isAuthenticated());
        AuthenticationAccessTokenResponseSchemaAdapter authentication =
            assertInstanceOf(AuthenticationAccessTokenResponseSchemaAdapter.class, response.getAuthentication().orElseThrow());
        assertNotNull(authentication.getAccessToken());
        assertEquals(3, authentication.getAccessToken().split("\\.").length, "access token should be a JWT");
        assertNotNull(authentication.getRefreshToken());
        assertEquals(3600, authentication.getExpiresIn());
        assertEquals(EMAIL, authentication.getAttributes().get("email"));
        assertEquals(authentication.getResponse().user().id(), authentication.getName());
        assertTrue(authentication.getRoles().contains("authenticated"));
    }

    @Test
    void wrongPasswordIsRejectedAsCredentialsDoNotMatch() {
        AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials(EMAIL, "wrong-password"));

        assertFalse(response.isAuthenticated());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, response).getReason());
    }

    @Test
    void unknownUserIsRejectedWithoutRevealingWhetherItExists() {
        AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials("nobody@example.com", PASSWORD));

        assertFalse(response.isAuthenticated());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, response).getReason());
    }

    @Test
    void blankPasswordIsRejectedWithoutCallingSupabase() {
        AuthenticationResponse response = provider.authenticate(null, new UsernamePasswordCredentials(EMAIL, ""));

        assertFalse(response.isAuthenticated());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, response).getReason());
    }
}
