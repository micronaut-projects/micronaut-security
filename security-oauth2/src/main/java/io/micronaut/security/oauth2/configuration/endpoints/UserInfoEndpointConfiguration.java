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
package io.micronaut.security.oauth2.configuration.endpoints;

import java.util.Optional;

/**
 * Configuration for the <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">UserInfo</a> endpoint of an OpenID provider.
 *
 * @author Sergio del Amo
 * @since 4.18.2
 */
public interface UserInfoEndpointConfiguration extends EndpointConfiguration {

    /**
     * Whether bearer tokens which cannot be attributed to this provider (opaque tokens, or JWTs without an {@code iss} claim) are sent to this provider's UserInfo endpoint for validation.
     * JWTs whose {@code iss} claim identifies a different issuer are never sent, regardless of this setting. A JWT whose issuer is expected by several providers cannot be attributed to one of them and is handled like an opaque token.
     *
     * @return {@code true} to always send such tokens, {@code false} to never send them, or empty to send them only when this is the only OpenID client configured.
     */
    Optional<Boolean> getValidateOpaqueTokens();
}
