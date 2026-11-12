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
package io.micronaut.security.oauth2.metadata;

import io.micronaut.core.util.Toggleable;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

/**
 * Protected Resource Metadata Configuration.
 * @since 4.14.0
 */
public interface ProtectedResourceMetadataConfiguration extends Toggleable {
    String PATH = "/.well-known/oauth-protected-resource";
    String PREFIX = OauthConfigurationProperties.PREFIX + ".protected-resource-metadata";
    String PROPERTY_WWW_AUTHENTICATE = PREFIX + ".www-authenticate";
    String PROPERTY_ENABLED = PREFIX + ".enabled";
}
