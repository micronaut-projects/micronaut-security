/*
 * Copyright 2017-2023 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.token.response;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationMode;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.errors.ObtainingAuthorizationErrorCode;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.CookieLoginHandler;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.security.token.cookie.LoginCookieProvider;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Sets {@link CookieLoginHandler}`s cookie value to the idtoken received from an authentication provider.
 * The cookie expiration is set to the expiration of the IDToken exp claim.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
@Requires(classes = HttpRequest.class)
@Singleton
public class IdTokenLoginHandler extends CookieLoginHandler {

    private static final Logger LOG = LoggerFactory.getLogger(IdTokenLoginHandler.class);
    private final List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders;
    private TokenConfiguration tokenConfiguration = new TokenConfiguration() { };

    /**
     * @param accessTokenCookieConfiguration Access token cookie configuration
     * @param redirectConfiguration Redirect configuration
     * @param redirectService Redirect service
     * @param priorToLoginPersistence The prior to login persistence strategy
     * @param loginCookieProviders List of beans of type {@link LoginCookieProvider}
     */
    @Inject
    public IdTokenLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                               RedirectConfiguration redirectConfiguration,
                               RedirectService redirectService,
                               @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence,
                               List<LoginCookieProvider<HttpRequest<?>>> loginCookieProviders) {
        super(accessTokenCookieConfiguration, redirectConfiguration, redirectService, priorToLoginPersistence);
        this.loginCookieProviders = loginCookieProviders;
    }

    /**
     * @param accessTokenCookieConfiguration Access token cookie configuration
     * @param redirectConfiguration Redirect configuration
     * @param redirectService Redirect service
     * @param priorToLoginPersistence The prior to login persistence strategy
     * @deprecated Use {@link #IdTokenLoginHandler(AccessTokenCookieConfiguration, RedirectConfiguration, RedirectService, PriorToLoginPersistence, List)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.11.0")
    public IdTokenLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                               RedirectConfiguration redirectConfiguration,
                               RedirectService redirectService,
                               @Nullable PriorToLoginPersistence<HttpRequest<?>, MutableHttpResponse<?>> priorToLoginPersistence) {
        this(accessTokenCookieConfiguration, redirectConfiguration, redirectService, priorToLoginPersistence, Collections.emptyList());
    }

    /**
     * Sets the Token Configuration used to name the authentication supplied to the {@link LoginCookieProvider} beans from
     * the ID token claims. Injected by method rather than by constructor so that subclasses using any constructor get the
     * application's configuration. Defaults to the default {@code micronaut.security.token.name-key}, {@code sub}.
     * @param tokenConfiguration Token Configuration
     * @since 5.5.2
     * @deprecated Method injection is used only to keep the existing constructors of this class and of its subclasses working.
     * This method will be removed in the next major release in favour of pure constructor injection, when the
     * {@code TokenConfiguration} becomes a constructor parameter. Subclasses should not rely on it.
     */
    @Deprecated(forRemoval = true, since = "5.5.2")
    @Inject
    public final void setTokenConfiguration(@NonNull TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request) {
        List<Cookie> cookies = new ArrayList<>(1);
        String accessToken = parseIdToken(authentication).orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        Cookie jwtCookie = Cookie.of(accessTokenCookieConfiguration.getCookieName(), accessToken);
        jwtCookie.configure(accessTokenCookieConfiguration, request.isSecure());
        warnIfInsecureCookie(jwtCookie, request);
        if (!accessTokenCookieConfiguration.isSessionCookie()) {
            jwtCookie.maxAge(cookieExpiration(authentication, request));
        }
        cookies.add(jwtCookie);
        Authentication tokenAuthentication = idTokenAuthentication(authentication, accessToken);
        for (LoginCookieProvider<HttpRequest<?>> loginCookieProvider : loginCookieProviders) {
            cookies.add(loginCookieProvider.provideCookie(request, tokenAuthentication));
        }
        return cookies;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Cookie> getCookies(Authentication authentication, String refreshToken, HttpRequest<?> request) {
        throw new OauthErrorResponseException(ObtainingAuthorizationErrorCode.INVALID_REQUEST, "Cannot refresh a provider token through the oauth endpoint. The token must be refreshed directly with the provider", null);
    }

    /**
     * The cookie issued at login carries the ID token, so later requests are named by token based authentication from
     * its claims: the {@link TokenConfiguration#getNameKey()} claim, falling back to the {@code sub} claim. The
     * user name returned by the {@code OpenIdAuthenticationMapper} at login (for example qualified with the provider
     * name) is not carried by the ID token, so the authentication supplied to the {@link LoginCookieProvider} beans is
     * named after the ID token claims instead.
     * @param authentication The authenticated user's representation
     * @param idToken The ID token
     * @return The authentication named as token based authentication names the user from the ID token, or the supplied
     * authentication if the ID token cannot be parsed or carries neither claim
     */
    @NonNull
    private Authentication idTokenAuthentication(@NonNull Authentication authentication, @NonNull String idToken) {
        try {
            JWTClaimsSet claims = JWTParser.parse(idToken).getJWTClaimsSet();
            Object name = claims.getClaim(tokenConfiguration.getNameKey());
            if (name == null) {
                name = claims.getClaim(Claims.SUBJECT);
            }
            if (name == null || name.toString().equals(authentication.getName())) {
                return authentication;
            }
            return Authentication.build(name.toString(), authentication.getRoles(), authentication.getAttributes());
        } catch (ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not parse the ID token to name the authentication supplied to the login cookie providers");
            }
            return authentication;
        }
    }

    /**
     * @param authentication User Details
     * @return parse the idtoken from the user details attributes
     */
    protected Optional<String> parseIdToken(Authentication authentication) {
        Map<String, Object> attributes = authentication.getAttributes();
        if (!attributes.containsKey(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("{} should be present in user details attributes to use {}:{}", OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, SecurityConfigurationProperties.PREFIX + ".authentication", AuthenticationMode.IDTOKEN);
            }
            return Optional.empty();
        }
        Object idTokenObjet = attributes.get(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY);
        if (!(idTokenObjet instanceof String)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("{} present in user details attributes should be of type String to use {}:{}", OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, SecurityConfigurationProperties.PREFIX + ".authentication", AuthenticationMode.IDTOKEN);
            }
            return Optional.empty();
        }
        return Optional.of((String) idTokenObjet);
    }

    /**
     * @param authentication User Details
     * @param request The current request
     * @return the expiration of the providers JWT
     */
    protected Duration cookieExpiration(Authentication authentication, HttpRequest<?> request) {
        Optional<String> idTokenOptional = parseIdToken(authentication);
        if (!idTokenOptional.isPresent()) {
            return Duration.ofSeconds(0);
        }
        String idToken = idTokenOptional.get();
        try {
            JWT jwt = JWTParser.parse(idToken);
            Date exp = jwt.getJWTClaimsSet().getExpirationTime();
            if (exp == null) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("unable to define a cookie expiration because id token exp claim is not set");
                }
                return Duration.ofSeconds(0);
            }
            return Duration.between(new Date().toInstant(), exp.toInstant());
        } catch (ParseException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("unable to define a cookie expiration because id token cannot be parsed to JWT");
            }
        }
        return Duration.ofSeconds(0);
    }
}
