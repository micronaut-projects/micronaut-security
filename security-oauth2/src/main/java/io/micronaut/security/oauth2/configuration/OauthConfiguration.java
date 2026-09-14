/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.configuration;

import org.jspecify.annotations.NonNull;
import io.micronaut.core.util.Toggleable;
import java.util.Optional;

/**
 * OAuth 2.0 Configuration.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface OauthConfiguration extends Toggleable {

    /**
     *
     * @return the login Uri
     */
    @NonNull
    String getLoginUri();

    /**
     * @return the Callback Uri
     */
    @NonNull
    String getCallbackUri();

    /**
     * @return the default authorization provider
     */
    Optional<String> getDefaultProvider();

    /**
     *
     * @return OpenID Connect Configuration
     */
    @NonNull
    OpenIdConfiguration getOpenid();

    /**
     * An optional fixed base URL (scheme, host and optional port, for example {@code https://app.example.com}) used to build
     * absolute URLs such as the OAuth 2.0 callback {@code redirect_uri}, the OpenID Connect {@code post_logout_redirect_uri},
     * and the protected resource metadata {@code resource} and {@code resource_metadata} values.
     * When empty, those URLs are derived from the request via {@code io.micronaut.http.server.util.HttpHostResolver}, which by
     * default trusts the {@code Host} and {@code Forwarded} / {@code X-Forwarded-*} request headers.
     *
     * @return the base URL, without a trailing slash, or empty to derive it from the request
     * @since 5.4.0
     */
    @NonNull
    default Optional<String> getBaseUrl() {
        return Optional.empty();
    }
}
