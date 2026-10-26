/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.oauth2.client.condition;

import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import org.jspecify.annotations.NonNull;

/**
 * Utility used by client conditions to verify that an OAuth 2.0 client has a client id configured.
 *
 * @author Sergio del Amo
 * @since 5.4.0
 */
@Internal
public final class ClientIdConditionUtils {

    private ClientIdConditionUtils() {
    }

    /**
     * Fails the condition if the client configuration does not define a client id.
     *
     * @param clientConfiguration The client configuration
     * @param context The condition context
     * @param failureMessagePrefix The failure message prefix
     * @return {@code true} if a client id is configured
     */
    public static boolean hasClientId(@NonNull OauthClientConfiguration clientConfiguration,
                                      @NonNull ConditionContext<?> context,
                                      @NonNull String failureMessagePrefix) {
        if (StringUtils.hasText(clientConfiguration.getClientId())) {
            return true;
        }
        context.fail(failureMessagePrefix + "] because no client id is configured. Set "
            + OauthConfigurationProperties.PREFIX + ".clients." + clientConfiguration.getName() + ".client-id");
        return false;
    }
}
