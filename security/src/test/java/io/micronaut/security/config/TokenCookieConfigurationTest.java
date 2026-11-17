package io.micronaut.security.config;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.env.yaml.YamlPropertySourceLoader;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.RefreshTokenCookieConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class TokenCookieConfigurationTest {

    @Test
    void iSessionCookieDefaultsToFalse() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-max-age", "5m"
        ))) {
            TokenCookieConfiguration tokenCookieConfiguration = ctx.getBean(TokenCookieConfiguration.class);
            assertFalse(tokenCookieConfiguration.isSessionCookie());
            assertTrue(tokenCookieConfiguration.getCookieMaxAge().isPresent());
        }

        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.session-cookie", StringUtils.TRUE,
            "micronaut.security.token.cookie.cookie-max-age", "5m"
        ))) {
            TokenCookieConfiguration tokenCookieConfiguration = ctx.getBean(TokenCookieConfiguration.class);
            assertTrue(tokenCookieConfiguration.isSessionCookie());
            // by setting session-cookie to true, the cookie-max-age should be ignored
            assertFalse(tokenCookieConfiguration.getCookieMaxAge().isPresent());
        }

    }

    @Test
    void sameSiteDefaultsToLaxForAccessTokenAndRefreshTokenCookies() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie"))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertEquals(SameSite.Lax, accessTokenCookieConfiguration.getCookieSameSite().orElse(null));

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertEquals(SameSite.Lax, refreshTokenCookieConfiguration.getCookieSameSite().orElse(null));
        }
    }

    @Test
    void refreshTokenCookieMaxAgeDefaultsToThirtyDays() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie"))) {
            assertEquals(Duration.ofDays(30), ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieMaxAge().orElse(null));
            assertFalse(ctx.getBean(AccessTokenCookieConfiguration.class).getCookieMaxAge().isPresent());
        }
    }

    @Test
    void refreshTokenCookieMaxAgeCanBeOverriddenAndIsIgnoredForSessionCookies() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.refresh.cookie.cookie-max-age", "5m"))) {
            assertEquals(Duration.ofMinutes(5), ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieMaxAge().orElse(null));
        }
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.refresh.cookie.session-cookie", "true"))) {
            assertFalse(ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieMaxAge().isPresent());
        }
    }

    @Test
    void cookieSecureHasNoDefault() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie"))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertFalse(accessTokenCookieConfiguration.isCookieSecure().isPresent());

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertFalse(refreshTokenCookieConfiguration.isCookieSecure().isPresent());
        }
    }

    @ParameterizedTest
    @EnumSource(SameSite.class)
    void sameSiteCanBeOverriddenForAccessTokenAndRefreshTokenCookies(SameSite sameSite) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", sameSite.name(),
            "micronaut.security.token.refresh.cookie.cookie-same-site", sameSite.name()
        ))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertEquals(sameSite, accessTokenCookieConfiguration.getCookieSameSite().orElse(null));

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertEquals(sameSite, refreshTokenCookieConfiguration.getCookieSameSite().orElse(null));
        }
    }

    @Test
    void sameSiteCanBeOverriddenIndependently() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", "Strict"
        ))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertEquals(SameSite.Strict, accessTokenCookieConfiguration.getCookieSameSite().orElse(null));

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertEquals(SameSite.Lax, refreshTokenCookieConfiguration.getCookieSameSite().orElse(null));
        }
    }

    @Test
    void emptySameSiteOmitsTheAttributeForAccessTokenAndRefreshTokenCookies() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", "",
            "micronaut.security.token.refresh.cookie.cookie-same-site", ""
        ))) {
            assertFalse(ctx.getBean(AccessTokenCookieConfiguration.class).getCookieSameSite().isPresent());
            assertFalse(ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieSameSite().isPresent());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"lax", "LAX", "Lax"})
    void sameSiteIsCaseInsensitive(String value) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", value,
            "micronaut.security.token.refresh.cookie.cookie-same-site", value
        ))) {
            assertEquals(SameSite.Lax, ctx.getBean(AccessTokenCookieConfiguration.class).getCookieSameSite().orElse(null));
            assertEquals(SameSite.Lax, ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieSameSite().orElse(null));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"bogus", " Lax ", "Lax,Strict"})
    void unrecognizedSameSiteOmitsTheAttribute(String value) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", value,
            "micronaut.security.token.refresh.cookie.cookie-same-site", value
        ))) {
            assertFalse(ctx.getBean(AccessTokenCookieConfiguration.class).getCookieSameSite().isPresent());
            assertFalse(ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieSameSite().isPresent());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"cookie-same-site: ''", "cookie-same-site: ~", "cookie-same-site:"})
    void emptySameSiteInYamlOmitsTheAttribute(String yamlEntry) throws IOException {
        String yaml = """
            micronaut:
              security:
                authentication: cookie
                token:
                  cookie:
                    %s
                  refresh:
                    cookie:
                      %s
            """.formatted(yamlEntry, yamlEntry);
        Map<String, Object> configuration = new YamlPropertySourceLoader().read("test", new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));
        try (ApplicationContext ctx = ApplicationContext.run(configuration)) {
            assertFalse(ctx.getBean(AccessTokenCookieConfiguration.class).getCookieSameSite().isPresent());
            assertFalse(ctx.getBean(RefreshTokenCookieConfiguration.class).getCookieSameSite().isPresent());
        }
    }
}
