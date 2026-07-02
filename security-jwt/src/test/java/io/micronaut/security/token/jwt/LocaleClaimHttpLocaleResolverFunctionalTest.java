package io.micronaut.security.token.jwt;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.server.util.locale.CookieLocaleResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.LocaleClaimHttpLocaleResolver;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.server.locale-resolution.cookie-name", value = "locale")
@Property(name = SecurityConfigurationProperties.PREFIX + ".authentication", value = "bearer")
@Property(name = SecurityConfigurationProperties.PREFIX + ".token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "spec.name", value = "LocaleClaimHttpLocaleResolverTest")
@MicronautTest
class LocaleClaimHttpLocaleResolverFunctionalTest {
    @Inject
    BeanContext beanContext;

    @Test
    void localeClaimHttpLocaleResolverLowPrecedence() {
        Collection<HttpLocaleResolver> resolvers = new ArrayList<>(beanContext.getBeansOfType(HttpLocaleResolver.class));
        int cookieLocaleResolverIndex = indexOf(resolvers, CookieLocaleResolver.class);
        int localeClaimHttpLocaleResolverIndex = indexOf(resolvers, LocaleClaimHttpLocaleResolver.class);
        assertTrue(cookieLocaleResolverIndex != -1);
        assertTrue(localeClaimHttpLocaleResolverIndex != -1);
        assertTrue(cookieLocaleResolverIndex < localeClaimHttpLocaleResolverIndex);
    }

    @Test
    void localeCanBeResolvedFromAClaim(TokenGenerator tokenGenerator,
                                       @Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();
        final String token = tokenGenerator.generateToken(Authentication.build("sergio", Collections.emptyList(), Map.of("locale", Locale.of("es", "ES"))), 3600).orElseThrow();
        String response = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET("/hola").bearerAuth(token).accept(MediaType.TEXT_PLAIN)));
        assertEquals("Hola Mundo", response);

        final String tokenWithClaimAsBCP47LanguageTag = tokenGenerator.generateToken(Authentication.build("sergio", Collections.emptyList(), Map.of("locale", "es-ES")), 3600).orElseThrow();
        response = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET("/hola").bearerAuth(tokenWithClaimAsBCP47LanguageTag).accept(MediaType.TEXT_PLAIN)));
        assertEquals("Hola Mundo", response);

        final String tokenWithoutLocaleClaim = tokenGenerator.generateToken(Authentication.build("sergio"), 3600).orElseThrow();
        response = assertDoesNotThrow(() -> client.retrieve(HttpRequest.GET("/hola").bearerAuth(tokenWithoutLocaleClaim).accept(MediaType.TEXT_PLAIN)));
        assertEquals("Hello World", response);
    }

    @Requires(property = "spec.name", value = "LocaleClaimHttpLocaleResolverTest")
    @Controller
    static class HellWorldController {

        private final HttpLocaleResolver resolver;

        HellWorldController(HttpLocaleResolver resolver) {
            this.resolver = resolver;
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get ("/hola")
        String index(HttpRequest<?> request) {
            Locale locale = resolver.resolveOrDefault(request);
            if (locale.equals(Locale.of("es", "ES"))) {
                return "Hola Mundo";
            }
            return "Hello World";
        }

    }

    private static int indexOf(Collection<HttpLocaleResolver> resolvers, Class<? extends HttpLocaleResolver> type) {
        int index = 0;
        for (HttpLocaleResolver resolver : resolvers) {
            if (type.isInstance(resolver)) {
                return index;
            }
            index++;
        }
        return -1;
    }
}
