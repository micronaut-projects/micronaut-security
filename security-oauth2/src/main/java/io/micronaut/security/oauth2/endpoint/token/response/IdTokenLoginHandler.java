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
import com.nimbusds.jwt.JWTParser;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
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
     * {@inheritDoc}
     */
    @Override
    public List<Cookie> getCookies(Authentication authentication, HttpRequest<?> request) {
        List<Cookie> cookies = new ArrayList<>(1);
        String accessToken = parseIdToken(authentication).orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        Cookie jwtCookie = Cookie.of(accessTokenCookieConfiguration.getCookieName(), accessToken);
        jwtCookie.configure(accessTokenCookieConfiguration, request.isSecure());
        jwtCookie.maxAge(cookieExpiration(authentication, request));
        cookies.add(jwtCookie);
        for (LoginCookieProvider<HttpRequest<?>> loginCookieProvider : loginCookieProviders) {
            cookies.add(loginCookieProvider.provideCookie(request));
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
