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
package io.micronaut.security.token.jwt.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.validator.TokenValidator;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;
import io.micronaut.validation.Validated;
import io.reactivex.Single;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import java.util.Optional;

/**
 *
 * A controller that handles token refresh.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(property = OauthControllerConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE)
@Requires(beans = RefreshTokenPersistence.class)
@Controller("${" + OauthControllerConfigurationProperties.PREFIX + ".path:/oauth/access_token}")
@Secured(SecurityRule.IS_ANONYMOUS)
@Validated
public class OauthController {

    private static final Logger LOG = LoggerFactory.getLogger(OauthController.class);
    protected final TokenValidator tokenValidator;
    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    private final RefreshTokenPersistence refreshTokenPersistence;
    private final RefreshTokenValidator refreshTokenValidator;

    /**
     *
     * @param tokenValidator An instance of {@link TokenValidator}
     * @param accessRefreshTokenGenerator An instance of {@link AccessRefreshTokenGenerator}
     */
    public OauthController(JwtTokenValidator tokenValidator,
                           AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                           RefreshTokenPersistence refreshTokenPersistence,
                           RefreshTokenValidator refreshTokenValidator) {
        this.tokenValidator = tokenValidator;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
        this.refreshTokenPersistence = refreshTokenPersistence;
        this.refreshTokenValidator = refreshTokenValidator;
    }

    /**
     *
     * @param tokenRefreshRequest An instance of {@link TokenRefreshRequest} present in the request
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    public Single<HttpResponse<AccessRefreshToken>> index(@Valid TokenRefreshRequest tokenRefreshRequest) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("grantType: {} refreshToken: {}", tokenRefreshRequest.getGrantType(), tokenRefreshRequest.getRefreshToken());
        }

        Publisher<UserDetails> userDetailsPublisher = refreshTokenValidator.validate(tokenRefreshRequest.getRefreshToken())
                .map(refreshTokenPersistence::getUserDetails)
                .orElseGet(Publishers::empty);

        return Single.fromPublisher(userDetailsPublisher)
            .map(userDetails -> {
            Optional<AccessRefreshToken> accessRefreshToken = accessRefreshTokenGenerator.generate(tokenRefreshRequest.getRefreshToken(), userDetails);
            if (accessRefreshToken.isPresent()) {
                return HttpResponse.ok(accessRefreshToken.get());
            }
            return HttpResponse.serverError();
        });
    }
}
