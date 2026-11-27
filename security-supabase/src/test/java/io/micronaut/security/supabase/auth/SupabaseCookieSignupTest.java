package io.micronaut.security.supabase.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.endpoints.SignupController;
import io.micronaut.supabase.auth.SupabaseAuthClient;
import io.micronaut.supabase.auth.SupabaseAuthRequests.TokenRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * An HTML signup form posted to {@link SignupController} in cookie authentication mode: Supabase creates the user
 * and {@link SupabaseSignupHandler} redirects to the configured signup success or failure URL, as the cookie login
 * handler does.
 */
@Testcontainers(disabledWithoutDocker = true)
@Property(name = "spec.name", value = "SupabaseCookieSignupTest")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.redirect.signup.success", value = "/signin?signedUp=true")
@Property(name = "micronaut.security.redirect.signup.failure", value = "/signup/failed")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SupabaseCookieSignupTest implements TestPropertyProvider {

    @Inject
    SupabaseAuthClient supabase;

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Override
    public @NonNull Map<String, String> getProperties() {
        return Supabase.getProperties();
    }

    @Test
    void signupFormRedirectsToSignupSuccessAndCreatesTheUser() {
        HttpResponse<?> response = submit(Map.of("email", "dave@example.com", "password", Supabase.TEST_PASSWORD));

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        assertEquals("/signin?signedUp=true", response.header(HttpHeaders.LOCATION));
        assertNull(response.header(HttpHeaders.SET_COOKIE), "signup does not sign the user in");
        TokenRequest grant = new TokenRequest(null, Supabase.TEST_PASSWORD, "dave@example.com", null,
            null, null, null, null, null, null, null, null, null, null, null, null);
        assertEquals(HttpStatus.OK, supabase.token("password", grant).getStatus());
    }

    @Test
    void signupFormRejectedBySupabaseRedirectsToSignupFailure() {
        HttpResponse<?> response = submit(Map.of("email", "erin@example.com", "password", "123"));

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        assertEquals("/signup/failed", response.header(HttpHeaders.LOCATION));
    }

    @Test
    void signupFormWithAlreadyRegisteredEmailRedirectsToSignupFailure() {
        Map<String, String> form = Map.of("email", "frank@example.com", "password", Supabase.TEST_PASSWORD);
        assertEquals("/signin?signedUp=true", submit(form).header(HttpHeaders.LOCATION));

        HttpResponse<?> response = submit(form);

        assertEquals(HttpStatus.SEE_OTHER, response.getStatus());
        assertEquals("/signup/failed", response.header(HttpHeaders.LOCATION));
    }

    private HttpResponse<?> submit(Map<String, String> form) {
        BlockingHttpClient client = httpClient.toBlocking();
        return client.exchange(HttpRequest.POST("/signup", form).contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE));
    }
}
