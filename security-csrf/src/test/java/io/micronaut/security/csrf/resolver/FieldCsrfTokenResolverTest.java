package io.micronaut.security.csrf.resolver;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.*;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.csrf.repository.CsrfTokenRepository;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Property(name = "spec.name", value = "FieldCsrfTokenResolverTest")
@MicronautTest
class FieldCsrfTokenResolverTest {

    @Inject
    BeanContext beanContext;

    @Test
    void fieldTokenResolver(@Client("/") HttpClient httpClient,
                            CsrfTokenGenerator<HttpRequest<?>> csrfTokenGenerator) {
        BlockingHttpClient client = httpClient.toBlocking();
        String csrfToken = csrfTokenGenerator.generateCsrfToken(new SimpleHttpRequest<>(HttpMethod.POST,"/password/change", "username=sherlock&password=elementary"));
        beanContext.registerSingleton(new CsrfTokenRepositoryReplacement(csrfToken));
        HttpRequest<?> request = HttpRequest.POST("/password/change", "username=sherlock&csrfToken="+ csrfToken + "&password=elementary")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.TEXT_HTML);
        String result = assertDoesNotThrow(() -> client.retrieve(request));
        assertEquals("sherlock", result);
    }

    @Requires(property = "spec.name", value = "FieldCsrfTokenResolverTest")
    static class CsrfTokenRepositoryReplacement implements CsrfTokenRepository<HttpRequest<?>> {
        private final String csrfToken;
        CsrfTokenRepositoryReplacement(String csrfToken) {
            this.csrfToken = csrfToken;
        }
        @Override
        @NonNull
        public Optional<String> findCsrfToken(@NonNull HttpRequest<?> request) {
            return Optional.of(csrfToken);
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