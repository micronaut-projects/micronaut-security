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
package io.micronaut.security.config;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.security.authentication.AuthenticationMode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Stores configuration for JWT.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@ConfigurationProperties(SecurityConfigurationProperties.PREFIX)
public class SecurityConfigurationProperties implements SecurityConfiguration {

    public static final String PREFIX = "micronaut.security";
    public static final String ANYWHERE = "0.0.0.0";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;
    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final AuthenticationStrategy DEFAULT_AUTHENTICATION_STRATEGY = AuthenticationStrategy.ANY;
    public static final boolean DEFAULT_REJECT_NOT_FOUND = true;

    private boolean enabled = DEFAULT_ENABLED;
    private List<InterceptUrlMapPattern> interceptUrlMap = new ArrayList<>();
    private List<String> ipPatterns = Collections.singletonList(ANYWHERE);
    private AuthenticationStrategy authenticationProviderStrategy = DEFAULT_AUTHENTICATION_STRATEGY;
    private boolean rejectNotFound = DEFAULT_REJECT_NOT_FOUND;

    @Nullable
    private AuthenticationMode authentication = null;

    @Override
    @Nullable
    public AuthenticationMode getAuthentication() {
        return authentication;
    }

    /**
     * Defines which authentication to use. Defaults to null. Possible values bearer, session, cookie. Should
     * only be supplied if the service handles login and logout requests.
     * @param authentication Login Handler Mode
     */
    public void setAuthentication(@Nullable AuthenticationMode authentication) {
        this.authentication = authentication;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    @Override
    public List<InterceptUrlMapPattern> getInterceptUrlMap() {
        return interceptUrlMap;
    }

    @Override
    public List<String> getIpPatterns() {
        return ipPatterns;
    }

    /**
     * If Security is enabled. Default value {@value #DEFAULT_ENABLED}
     *
     * @param enabled True if security is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Map that defines the interception patterns.
     *
     * @param interceptUrlMap The intercept urls maps
     */
    public void setInterceptUrlMap(List<InterceptUrlMapPattern> interceptUrlMap) {
        if (CollectionUtils.isNotEmpty(interceptUrlMap)) {
            this.interceptUrlMap = interceptUrlMap;
        }
    }

    /**
     * Allowed IP patterns. Default value ([{@value #ANYWHERE}])
     *
     * @param ipPatterns The IP patterns
     */
    public void setIpPatterns(List<String> ipPatterns) {
        this.ipPatterns = ipPatterns;
    }

    @Override
    public AuthenticationStrategy getAuthenticationProviderStrategy() {
        return authenticationProviderStrategy;
    }

    /**
     * Determines how authentication providers should be processed. Default value ANY. Possible values: ANY or ALL.
     * @param authenticationProviderStrategy authentication strategy.
     */
    public void setAuthenticationProviderStrategy(AuthenticationStrategy authenticationProviderStrategy) {
        this.authenticationProviderStrategy = authenticationProviderStrategy;
    }

    @Override
    public boolean isRejectNotFound() {
        return rejectNotFound;
    }

    /**
     * @param rejectNotFound Set to true if the server should respond with 404 for requests that do not
     *      * match any routes on the server. Default value ({#DEFAULT_REJECT_NOT_FOUND}).
     */
    public void setRejectNotFound(boolean rejectNotFound) {
        this.rejectNotFound = rejectNotFound;
    }
}
