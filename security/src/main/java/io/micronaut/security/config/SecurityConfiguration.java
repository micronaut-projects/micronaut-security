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
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.handlers.LoginHandlerMode;
import io.micronaut.security.handlers.LogoutHandlerMode;

import java.util.List;

/**
 * Defines security configuration properties.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public interface SecurityConfiguration extends Toggleable {

    /**
     * @return a list of IP Regex patterns. e.g. [192.168.1.*]
     */
    List<String> getIpPatterns();

    /**
     * @return a list of {@link InterceptUrlMapPattern}
     */
    List<InterceptUrlMapPattern> getInterceptUrlMap();

    /**
     * @return The authentication strategy
     */
    default AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.ANY;
    }

    /**
     * For cases where no security rule handles a request and it is determined
     * that the request does not match any routes on the server, whether the response
     * should be to reject the request or allow the not found response to be returned.
     *
     * @return True if the response should be rejected.
     */
    default boolean isRejectNotFound() {
        return true;
    }

    /**
     *
     * @return Login Handler to use.
     */
    @Nullable
    LoginHandlerMode getLoginHandler();


    /**
     *
     * @return Logout Handler to use.
     */
    @Nullable
    LogoutHandlerMode getLogoutHandler();
}
