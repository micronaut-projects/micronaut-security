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
package io.micronaut.security.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.CookieValue;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.errors.IssuingAnAccessTokenErrorCode;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.validator.RefreshTokenValidator;

import java.util.Map;
import java.util.Optional;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import static io.micronaut.security.endpoints.TokenRefreshRequest.GRANT_TYPE;


/**
 *
 * A controller that handles token refresh.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-6">Refreshing an Access token</a>
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(property = OauthControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(classes = Controller.class)
@Requires(beans = RefreshTokenPersistence.class)
@Requires(beans = RefreshTokenValidator.class)
@Controller("${" + OauthControllerConfigurationProperties.PREFIX + ".path:/oauth/access_token}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class OauthController {

    private final RefreshTokenPersistence refreshTokenPersistence;
    private final RefreshTokenValidator refreshTokenValidator;
    private final OauthControllerConfigurationProperties oauthControllerConfigurationProperties;
    private final LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler;

    /**
     * @param refreshTokenPersistence The persistence mechanism for the refresh token
     * @param refreshTokenValidator The refresh token validator
     * @param oauthControllerConfigurationProperties The controller configuration
     * @param loginHandler The login handler
     */
    public OauthController(RefreshTokenPersistence refreshTokenPersistence,
                           RefreshTokenValidator refreshTokenValidator,
                           OauthControllerConfigurationProperties oauthControllerConfigurationProperties,
                           LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler) {
        this.refreshTokenPersistence = refreshTokenPersistence;
        this.refreshTokenValidator = refreshTokenValidator;
        this.oauthControllerConfigurationProperties = oauthControllerConfigurationProperties;
        this.loginHandler = loginHandler;
    }

    /**
     * @param request The current request
     * @param body HTTP Request body which will be mapped to a {@link TokenRefreshRequest}.
     * @param cookieRefreshToken The refresh token stored in a cookie
     * @return A response or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    @SingleResult
    public Publisher<MutableHttpResponse<?>> index(HttpRequest<?> request,
                                                   @Nullable @Body Map<String, String> body,
                                                   @Nullable @CookieValue("JWT_REFRESH_TOKEN") String cookieRefreshToken) {
        TokenRefreshRequest tokenRefreshRequest = body == null ? null :
            new TokenRefreshRequest(body.get(GRANT_TYPE), body.get(TokenRefreshRequest.GRANT_TYPE_REFRESH_TOKEN));
        String refreshToken = resolveRefreshToken(tokenRefreshRequest, cookieRefreshToken);
        return createResponse(request, refreshToken);
    }

    /**
     * @param request The current request
     * @param cookieRefreshToken The refresh token stored in a cookie
     * @return A response or a failure indicated by the HTTP status
     */
    @Get
    @SingleResult
    public Publisher<MutableHttpResponse<?>> index(HttpRequest<?> request,
                                                   @Nullable @CookieValue("JWT_REFRESH_TOKEN") String cookieRefreshToken) {
        if (!oauthControllerConfigurationProperties.isGetAllowed()) {
            return Mono.just(HttpResponse.status(HttpStatus.METHOD_NOT_ALLOWED));
        }
        String refreshToken = resolveRefreshToken(null, cookieRefreshToken);
        return createResponse(request, refreshToken);
    }

    @SingleResult
    private Publisher<MutableHttpResponse<?>> createResponse(HttpRequest<?> request, String refreshToken) {
        Optional<String> validRefreshToken = refreshTokenValidator.validate(refreshToken);
        if (!validRefreshToken.isPresent()) {
            throw new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.INVALID_GRANT, "Refresh token is invalid", null);
        }
        return Mono.from(refreshTokenPersistence.getAuthentication(validRefreshToken.get()))
                .map(authentication -> loginHandler.loginRefresh(authentication, refreshToken, request));
    }

    @NonNull
    private String resolveRefreshToken(TokenRefreshRequest tokenRefreshRequest, String cookieRefreshToken) {
        String refreshToken = null;
        if (tokenRefreshRequest != null) {
            if (StringUtils.isEmpty(tokenRefreshRequest.getGrantType()) || StringUtils.isEmpty(tokenRefreshRequest.getRefreshToken())) {
                throw new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.INVALID_REQUEST, "refresh_token and grant_type are required", null);
            }
            if (!tokenRefreshRequest.getGrantType().equals(TokenRefreshRequest.GRANT_TYPE_REFRESH_TOKEN)) {
                throw new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.UNSUPPORTED_GRANT_TYPE, "grant_type must be refresh_token", null);
            }
            refreshToken = tokenRefreshRequest.getRefreshToken();
        } else if (cookieRefreshToken != null) {
            refreshToken = cookieRefreshToken;
        } else {
            throw new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.INVALID_REQUEST, "refresh_token and grant_type are required", null);
        }
        if (StringUtils.isEmpty(refreshToken)) {
            throw new OauthErrorResponseException(IssuingAnAccessTokenErrorCode.INVALID_REQUEST, "refresh_token is required", null);
        }
        return refreshToken;
    }
}
