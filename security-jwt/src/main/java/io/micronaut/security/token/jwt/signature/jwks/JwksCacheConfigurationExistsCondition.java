/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.cache.CacheConfiguration;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.qualifiers.Qualifiers;
import java.util.Optional;

import static io.micronaut.security.token.jwt.signature.jwks.CacheableJwkSetFetcher.CACHE_JWKS;

@Internal
final class JwksCacheConfigurationExistsCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        try {
            Optional<CacheConfiguration> beanOptional = context.findBean(CacheConfiguration.class, Qualifiers.byName(CACHE_JWKS));
            if (beanOptional.isEmpty()) {
                context.fail("No bean of type io.micronaut.cache.CacheConfiguration and name qualifier " + CACHE_JWKS + " found");
            }
            return beanOptional.isPresent();
        } catch (ConfigurationException e) {
            context.fail("No bean of type io.micronaut.cache.CacheConfiguration and name qualifier " + CACHE_JWKS + " found");
            return false;
        }
    }
}
