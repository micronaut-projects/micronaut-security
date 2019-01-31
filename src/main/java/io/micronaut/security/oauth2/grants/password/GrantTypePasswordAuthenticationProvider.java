/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.grants.password;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse;
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponseValidator;
import io.micronaut.security.token.config.TokenConfiguration;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * {@link AuthenticationProvider} for Password Grant Type.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = GrantTypePasswordRequestProviderConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE)
@Requires(beans = {
        GrantTypePasswordRequestProvider.class,
        IdTokenAccessTokenResponseValidator.class,
        TokenConfiguration.class,
})
@Singleton
public class GrantTypePasswordAuthenticationProvider implements AuthenticationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(GrantTypePasswordAuthenticationProvider.class);

    private final GrantTypePasswordRequestProvider grantTypePasswordRequestProvider;
    private final IdTokenAccessTokenResponseValidator idTokenAccessTokenResponseValidator;
    private final TokenConfiguration tokenConfiguration;

    /**
     *
     * @param grantTypePasswordRequestProvider Grant type password request provider
     * @param idTokenAccessTokenResponseValidator IDToken/AccessToken response validator
     * @param tokenConfiguration Token Configuration
     */
    public GrantTypePasswordAuthenticationProvider(GrantTypePasswordRequestProvider grantTypePasswordRequestProvider,
                                                   IdTokenAccessTokenResponseValidator idTokenAccessTokenResponseValidator,
                                                   TokenConfiguration tokenConfiguration) {
        this.grantTypePasswordRequestProvider = grantTypePasswordRequestProvider;
        this.idTokenAccessTokenResponseValidator = idTokenAccessTokenResponseValidator;
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(AuthenticationRequest authenticationRequest) {

        if (authenticationRequest.getIdentity() instanceof String && authenticationRequest.getSecret() instanceof String) {
            HttpRequest request = grantTypePasswordRequestProvider.generateRequest((String) authenticationRequest.getIdentity(), (String) authenticationRequest.getSecret());
            RxHttpClient rxHttpClient;
            try {
                rxHttpClient = RxHttpClient.create(request.getUri().toURL());
            } catch (MalformedURLException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("malformed url {}", request.getUri(), e);
                }
                return Flowable.just(new AuthenticationFailed());
            }

            Flowable<HttpResponse<IdTokenAccessTokenResponse>> flowable = rxHttpClient.exchange(request, IdTokenAccessTokenResponse.class);
            return flowable.map(response -> {
                if (response.getBody().isPresent()) {
                    Optional<IdTokenAccessTokenResponse> idTokenAccessTokenResponseOpt = response.getBody();
                    if (idTokenAccessTokenResponseOpt.isPresent()) {
                        IdTokenAccessTokenResponse idTokenAccessTokenResponse = idTokenAccessTokenResponseOpt.get();
                        Optional<Authentication> authenticationOpt = idTokenAccessTokenResponseValidator.validate(idTokenAccessTokenResponse);
                        if (authenticationOpt.isPresent()) {
                            Authentication authentication = authenticationOpt.get();
                            return getUserDetails(authentication);
                        }
                    }
                }
                return new AuthenticationFailed();
            });
        } else {
            return Flowable.just(new AuthenticationFailed());
        }
    }

    /**
     *
     * @param authentication Authentication
     * @return User Details object
     */
    protected UserDetails getUserDetails(Authentication authentication) {
        return new UserDetails(authentication.getName(),
                getRoles(authentication, tokenConfiguration.getRolesName()));
    }

    /**
     *
     * @param authentication Authentication
     * @param rolesKey The key used for roles
     * @return a list of roles
     */
    protected List<String> getRoles(Authentication authentication, String rolesKey) {
        Object authorities = authentication.getAttributes().get(rolesKey);
        if (authorities instanceof List) {
            List<String> result = new ArrayList<>();
            for (Object obj : (List) authorities) {
                if (obj instanceof String) {
                    result.add((String) obj);
                }
            }
            return result;
        } else if (authorities instanceof String) {
            return Collections.singletonList((String) authorities);
        }

        return new ArrayList<>();
    }
}
