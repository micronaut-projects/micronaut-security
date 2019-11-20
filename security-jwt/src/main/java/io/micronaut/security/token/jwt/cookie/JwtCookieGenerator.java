package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.token.jwt.generator.JwtGeneratorConfiguration;

import javax.inject.Singleton;
import java.time.temporal.TemporalAmount;
import java.util.Optional;

@Requires(
        property = "micronaut.security.token.jwt.cookie.redirect.enabled",
        defaultValue = "true",
        value = "false"
)
@Singleton
public class JwtCookieGenerator {
    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final JwtGeneratorConfiguration jwtGeneratorConfiguration;

    public JwtCookieGenerator(JwtCookieConfiguration jwtCookieConfiguration, JwtGeneratorConfiguration jwtGeneratorConfiguration) {
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.jwtGeneratorConfiguration = jwtGeneratorConfiguration;
    }

    public Cookie generate(String accessToken, boolean isSecure) {
        Cookie cookie = Cookie.of(jwtCookieConfiguration.getCookieName(), accessToken);
        cookie.configure(jwtCookieConfiguration, isSecure);
        Optional<TemporalAmount> cookieMaxAge = jwtCookieConfiguration.getCookieMaxAge();
        if (cookieMaxAge.isPresent()) {
            cookie.maxAge(cookieMaxAge.get());
        } else {
            cookie.maxAge(jwtGeneratorConfiguration.getAccessTokenExpiration());
        }
        return cookie;
    }
}
