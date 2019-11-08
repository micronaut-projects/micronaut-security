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


/**
 * Classes implementing server authorization based on bearer token.
 *
 * @author svishnyakoff
 * @since 1.3.0
 */
@Requires(property = OAUTH_TOKEN_AUTHORIZATION_CONFIG + ".enabled", notEquals = StringUtils.FALSE)
@Configuration
package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;

import static io.micronaut.security.oauth2.bearer.ClientCredentialsTokenValidator.OAUTH_TOKEN_AUTHORIZATION_CONFIG;
