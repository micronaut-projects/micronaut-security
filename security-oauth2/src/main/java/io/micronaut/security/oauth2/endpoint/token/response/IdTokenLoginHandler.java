/*
 * Copyright 2017-2020 original authors
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
import io.micronaut.core.annotation.Nullable;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.errors.ObtainingAuthorizationErrorCode;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.authentication.AuthenticationMode;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.security.token.jwt.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.jwt.cookie.CookieLoginHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.inject.Singleton;
import java.text.ParseException;
import java.time.Duration;
import java.util.*;

/**
 * Sets {@link CookieLoginHandler}`s cookie value to the idtoken received from an authentication provider.
 * The cookie expiration is set to the expiration of the IDToken exp claim.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "idtoken")
@Singleton
public class IdTokenLoginHandler extends CookieLoginHandler {

    private static final Logger LOG = LoggerFactory.getLogger(IdTokenLoginHandler.class);

    private final TokenConfiguration tokenConfiguration;

    public IdTokenLoginHandler(AccessTokenCookieConfiguration accessTokenCookieConfiguration,
                               RedirectConfiguration redirectConfiguration,
                               TokenConfiguration tokenConfiguration,
                               @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        super(accessTokenCookieConfiguration, redirectConfiguration, priorToLoginPersistence);
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public List<Cookie> getCookies(UserDetails userDetails, HttpRequest<?> request) {
        List<Cookie> cookies = new ArrayList<>(1);
        String accessToken = parseIdToken(userDetails).orElseThrow(() -> new OauthErrorResponseException(ObtainingAuthorizationErrorCode.SERVER_ERROR, "Cannot obtain an access token", null));

        Cookie jwtCookie = Cookie.of(accessTokenCookieConfiguration.getCookieName(), accessToken);
        jwtCookie.configure(accessTokenCookieConfiguration, request.isSecure());
        jwtCookie.maxAge(cookieExpiration(userDetails, request));
        cookies.add(jwtCookie);
        return cookies;
    }

    @Override
    public List<Cookie> getCookies(UserDetails userDetails, String refreshToken, HttpRequest<?> request) {
        throw new OauthErrorResponseException(ObtainingAuthorizationErrorCode.INVALID_REQUEST, "Cannot refresh a provider token through the oauth endpoint. The token must be refreshed directly with the provider", null);
    }

    /**
     * @param userDetails User Details
     * @return parse the idtoken from the user details attributes
     */
    protected Optional<String> parseIdToken(UserDetails userDetails) {
        Map<String, Object> attributes = userDetails.getAttributes(tokenConfiguration.getRolesName(), tokenConfiguration.getNameKey());
        if (!attributes.containsKey(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("{} should be present in user details attributes to use {}:{}", OpenIdUserDetailsMapper.OPENID_TOKEN_KEY, SecurityConfigurationProperties.PREFIX + ".authentication", AuthenticationMode.IDTOKEN.toString());
            }
            return Optional.empty();
        }
        Object idTokenObjet = attributes.get(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY);
        if (!(idTokenObjet instanceof String)) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("{} present in user details attributes should be of type String to use {}:{}", OpenIdUserDetailsMapper.OPENID_TOKEN_KEY, SecurityConfigurationProperties.PREFIX + ".authentication", AuthenticationMode.IDTOKEN.toString());
            }
            return Optional.empty();
        }
        return Optional.of((String) idTokenObjet);
    }

    /**
     * @param userDetails User Details
     * @param request The current request
     * @return the expiration of the providers JWT
     */
    protected Duration cookieExpiration(UserDetails userDetails, HttpRequest<?> request) {
        Optional<String> idTokenOptional = parseIdToken(userDetails);
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
