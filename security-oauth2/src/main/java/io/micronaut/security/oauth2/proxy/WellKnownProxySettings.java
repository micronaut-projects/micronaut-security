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

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.Nullable;

import java.net.URL;

/**
 * Encapsulates behaviour for the {@link WellKnownProxyFilter}.
 * @param issuer The Authorization Server URL.
 * @param proxyWellKnownOauthAuthorizationServer Whether to proxy requests to /.well-known/oauth-authorization-server
 * @param proxyWellKnownOpenidConfiguration Whether to proxy requests to /.well-known/openid-configuration
 */
@Internal
record WellKnownProxySettings(
    @Nullable URL issuer,
    boolean proxyWellKnownOauthAuthorizationServer,
    boolean proxyWellKnownOpenidConfiguration
) {
}
