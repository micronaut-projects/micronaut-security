/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.proxy;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;

import java.net.URL;
import java.util.Collection;

/**
 * A condition which evaluates to true if there is at least one bean of type {@link OauthClientConfiguration} whose methods ({@link OauthClientConfiguration#isProxyWellKnownOauthAuthorizationServer()} or {@link OauthClientConfiguration#isProxyWellKnownOpenidConfiguration()}) return true and an issuer is set.
  */
@Internal
final class WellKnownProxyFilterCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context) {
        return issuer(context.getBeansOfType(OauthClientConfiguration.class)) != null;
    }

    @Nullable
    static URL issuer(@NonNull Collection<OauthClientConfiguration> oauthClientConfigurations) {
        if (CollectionUtils.isEmpty(oauthClientConfigurations)) {
            return null;
        }
        for (OauthClientConfiguration config : oauthClientConfigurations) {
            if (config.isProxyWellKnownOpenidConfiguration() || config.isProxyWellKnownOauthAuthorizationServer()) {
                URL issuer = issuer(config);
                if (issuer != null) {
                    return issuer;
                }
            }
        }
        return null;
    }

    @Nullable
    static URL issuer(OauthClientConfiguration oauthClientConfiguration) {
        return oauthClientConfiguration.getOpenid().flatMap(OpenIdClientConfiguration::getIssuer).orElse(null);
    }
}
