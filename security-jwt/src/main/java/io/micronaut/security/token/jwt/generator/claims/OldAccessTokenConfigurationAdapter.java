/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.jwt.generator.claims;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration;

/**
 * Adapts from {@link io.micronaut.security.token.generator.AccessTokenConfiguration} to {@link AccessTokenConfiguration}.
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Deprecated
@Internal
public class OldAccessTokenConfigurationAdapter implements  AccessTokenConfiguration {
    private final io.micronaut.security.token.generator.AccessTokenConfiguration accessTokenConfiguration;
    public OldAccessTokenConfigurationAdapter(io.micronaut.security.token.generator.AccessTokenConfiguration accessTokenConfiguration) {
        this.accessTokenConfiguration = accessTokenConfiguration;
    }

    @Override
    public Integer getExpiration() {
        return accessTokenConfiguration.getExpiration();
    }
}
