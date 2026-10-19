/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.supabase;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.http.BasicHttpAttributes;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.ClientFilter;
import io.micronaut.http.annotation.RequestFilter;

/**
 * Adds the Supabase API key to every request of the {@code supabase} HTTP client.
 *
 * <p>User-facing routes receive the {@linkplain SupabaseConfiguration#getPublishableKey() publishable key};
 * administrative routes, {@code /admin/**} and {@code /invite}, receive the
 * {@linkplain SupabaseConfiguration#getSecretKey() secret key}. The key is sent in the {@code apikey} header,
 * which is the only header the Supabase API gateway accepts the new key formats in. Nothing is added when
 * the corresponding key is not configured or the request already carries an {@code apikey} header.</p>
 *
 * <p>A legacy service-role key is a JWT, and GoTrue authorizes administrative routes from a bearer JWT with an
 * admin role. When the configured secret key is such a JWT and the request has no {@code Authorization}
 * header, the filter also sends it as a bearer token. The gateway allows that as long as both headers carry
 * the same value, and a self-hosted GoTrue server requires it. Opaque {@code sb_secret_} keys are never
 * placed in {@code Authorization}, where the gateway would reject them.</p>
 *
 * @since 0.0.1
 */
@Experimental
@ClientFilter(serviceId = SupabaseApiKeyClientFilter.SERVICE_ID)
@Requires(classes = ClientFilter.class)
@Requires(beans = SupabaseConfiguration.class)
public class SupabaseApiKeyClientFilter {

    /**
     * Service id of the Supabase HTTP client, configured under {@code micronaut.http.services.supabase}.
     */
    public static final String SERVICE_ID = "supabase";

    /**
     * Header that carries the Supabase API key.
     */
    public static final String APIKEY_HEADER = "apikey";

    private static final String ADMIN_PREFIX = "/admin/";
    private static final String INVITE_ROUTE = "/invite";
    private static final String LEGACY_JWT_PREFIX = "eyJ";

    private final SupabaseConfiguration configuration;

    /**
     * Creates the filter.
     *
     * @param configuration Supabase API keys
     */
    public SupabaseApiKeyClientFilter(SupabaseConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Adds the {@code apikey} header, and for legacy secret keys on administrative routes the bearer token.
     *
     * @param request Outgoing request
     */
    @RequestFilter
    public void filter(MutableHttpRequest<?> request) {
        boolean admin = isAdminRoute(BasicHttpAttributes.getUriTemplate(request).orElseGet(request::getPath));
        String key = admin ? configuration.getSecretKey() : configuration.getPublishableKey();
        if (key == null) {
            return;
        }
        if (!request.getHeaders().contains(APIKEY_HEADER)) {
            request.header(APIKEY_HEADER, key);
        }
        if (admin && isLegacyJwt(key) && !request.getHeaders().contains(HttpHeaders.AUTHORIZATION)) {
            request.bearerAuth(key);
        }
    }

    /**
     * Whether a route needs the secret key. GoTrue mounts administrative operations under {@code /admin} and
     * also requires admin credentials for {@code /invite}.
     *
     * @param path Request path or URI template, possibly prefixed by the Auth API base path
     * @return {@code true} for administrative routes
     */
    static boolean isAdminRoute(String path) {
        String withoutQuery = path.indexOf('?') >= 0 ? path.substring(0, path.indexOf('?')) : path;
        return withoutQuery.contains(ADMIN_PREFIX) || withoutQuery.endsWith(INVITE_ROUTE);
    }

    /**
     * Whether a key is a legacy JWT-based key rather than an opaque {@code sb_} key.
     *
     * @param key API key
     * @return {@code true} for a JWT
     */
    static boolean isLegacyJwt(String key) {
        return key.startsWith(LEGACY_JWT_PREFIX);
    }
}
