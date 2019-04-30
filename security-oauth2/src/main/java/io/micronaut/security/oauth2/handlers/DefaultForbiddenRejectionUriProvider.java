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

package io.micronaut.security.oauth2.handlers;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Secondary;
import io.micronaut.context.annotation.Value;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.handlers.ForbiddenRejectionUriProvider;
import io.micronaut.security.oauth2.endpoint.DeniedControllerConfigurationProperties;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * Default implementation of {@link ForbiddenRejectionUriProvider}.
 * @see <a href="https://docs.micronaut.io/1.1.0.M1/guide/index.html#rejection">Rejection Handling</a>.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + "default-forbidden-rejection-uri-provider", notEquals = StringUtils.FALSE)
@Secondary
@Singleton
public class DefaultForbiddenRejectionUriProvider implements ForbiddenRejectionUriProvider {

    /**
     *
     */
    public DefaultForbiddenRejectionUriProvider() {

    }

    @Override
    public Optional<String> getForbiddenRedirectUri(HttpRequest<?> request) {
        return Optional.of("/denied");
    }
}
