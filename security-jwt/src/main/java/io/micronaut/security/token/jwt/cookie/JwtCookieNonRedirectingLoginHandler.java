package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.generator.JwtGeneratorConfiguration;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;

import javax.inject.Singleton;
import java.util.Optional;

@Requires(
        property = "micronaut.security.token.jwt.cookie.redirect.enabled",
        defaultValue = "true",
        value = "false"
)
@Singleton
public class JwtCookieNonRedirectingLoginHandler implements LoginHandler {
    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final JwtGeneratorConfiguration jwtGeneratorConfiguration;
    protected final JwtCookieGenerator jwtCookieGenerator;

    /**
     * @param jwtCookieConfiguration      JWT Cookie Configuration
     * @param jwtGeneratorConfiguration   JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param jwtCookieGenerator
     */
    public JwtCookieNonRedirectingLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                                               JwtGeneratorConfiguration jwtGeneratorConfiguration,
                                               AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                               JwtCookieGenerator jwtCookieGenerator) {
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.jwtGeneratorConfiguration = jwtGeneratorConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
        this.jwtCookieGenerator = jwtCookieGenerator;
    }

    @Override
    public HttpResponse loginSuccess(UserDetails userDetails, HttpRequest<?> request) {
        Optional<AccessRefreshToken> accessRefreshTokenOptional = accessRefreshTokenGenerator.generate(userDetails);
        if (accessRefreshTokenOptional.isPresent()) {
            return HttpResponse
                    .ok()
                    .cookie(jwtCookieGenerator.generate(accessRefreshTokenOptional.get().getAccessToken(), request.isSecure()));

        }
        return HttpResponse.serverError();
    }

    @Override
    public HttpResponse loginFailed(AuthenticationFailed authenticationFailed) {
        return HttpResponse.unauthorized();
    }
}
