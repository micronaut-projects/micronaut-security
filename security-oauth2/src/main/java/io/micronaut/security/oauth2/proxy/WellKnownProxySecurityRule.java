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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

import java.util.List;

/**
 * Security rule which allows unauthenticated access for GET requests to the paths /.well-known/oauth-authorization-server or /.well-known/openid-configuration which are proxied to the authorization server by {@link WellKnownProxyFilter}.
 * A well-known path which is not proxied is not affected by this rule.
 * This rule is loaded only if {@link WellKnownProxyFilterCondition} condition evaluates to true.
 */
@Requires(condition = WellKnownProxyFilterCondition.class)
@Requires(classes = HttpRequest.class)
@Singleton
@Internal
final class WellKnownProxySecurityRule implements SecurityRule<HttpRequest<?>> {

    @Nullable
    private final WellKnownProxySettings settings;

    WellKnownProxySecurityRule(List<OauthClientConfiguration> oauthClientConfigurations) {
        this.settings = WellKnownProxyFilterCondition.issuer(oauthClientConfigurations);
    }

    @Override
    @NonNull
    public Publisher<SecurityRuleResult> check(@Nullable HttpRequest<?> request,
                                               @Nullable Authentication authentication) {
        if (request == null || settings == null || settings.issuer() == null || !request.getMethod().equals(HttpMethod.GET)) {
            return Publishers.just(SecurityRuleResult.UNKNOWN);
        }
        String path = request.getPath();
        if ((path.equals(WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH) && settings.proxyWellKnownOauthAuthorizationServer())
            || (path.equals(WellKnownProxyFilter.OPENID_CONFIGURATION_PATH) && settings.proxyWellKnownOpenidConfiguration())) {
            return Publishers.just(SecurityRuleResult.ALLOWED);
        }
        return Publishers.just(SecurityRuleResult.UNKNOWN);
    }
}
