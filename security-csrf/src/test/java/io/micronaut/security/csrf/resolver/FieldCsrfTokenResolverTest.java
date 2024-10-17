package io.micronaut.security.csrf.resolver;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.*;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.validator.CsrfTokenValidator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "FieldCsrfTokenResolverTest")
@MicronautTest
class FieldCsrfTokenResolverTest {

    @Test
    void fieldTokenResolver(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&csrfToken=abcde&password=elementary")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        String result = assertDoesNotThrow(() -> client.retrieve(request));
        assertEquals("sherlock", result);
    }

    @Requires(property = "spec.name", value = "FieldCsrfTokenResolverTest")
    @Singleton
    @Replaces(CsrfTokenValidator.class)
    static class CsrfTokenValidatorReplacement implements CsrfTokenValidator<HttpRequest<?>> {
        @Override
        public boolean validateCsrfToken(HttpRequest<?> request, String token) {
            return token.equals("abcde");
        }
    }

    @Requires(property = "spec.name", value = "FieldCsrfTokenResolverTest")
    @Controller
    static class PasswordChangeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.TEXT_HTML)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/password/change")
        String changePassword(@Body PasswordChangeForm passwordChangeForm) {
            return passwordChangeForm.username;
        }
    }

    @Serdeable
    record PasswordChangeForm(
        String username,
        String password,
        String csrfToken) {
    }
}