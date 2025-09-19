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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.rules.SecurityRuleResult;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

/**
 * Security rule which allows unauthenticated access for GET requests to paths /.well-known/oauth-authorization-server or /.well-known/openid-configuration.
 * This rule is loaded only if {@link WellKnownProxyFilterCondition} condition evaluates to true.
 */
@Requires(classes = HttpRequest.class)
@Singleton
final class WellKnownProxySecurityRule implements SecurityRule<HttpRequest<?>> {
    @Override
    @NonNull
    public Publisher<SecurityRuleResult> check(@Nullable HttpRequest<?> request,
                                               @Nullable Authentication authentication) {
        if (request == null) {
            return Publishers.just(SecurityRuleResult.UNKNOWN);
        }
        String path = request.getPath();
        if (request.getMethod().equals(HttpMethod.GET) &&
                (
                    path.equals(WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH)
                        || path.equals(WellKnownProxyFilter.OPENID_CONFIGURATION_PATH)
                )
        ) {
            return Publishers.just(SecurityRuleResult.ALLOWED);
        }
        return Publishers.just(SecurityRuleResult.UNKNOWN);
    }
}
