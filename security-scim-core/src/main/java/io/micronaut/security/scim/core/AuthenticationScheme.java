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
package io.micronaut.security.scim.core;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

/**
 * An authentication scheme advertised by a SCIM service provider.
 *
 * @param type The authentication scheme type
 * @param name The common scheme name
 * @param description A human-readable description
 * @param specUri The authentication specification URI
 * @param documentationUri The service provider's usage documentation URI
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record AuthenticationScheme(
    @NotBlank String type,
    @NotBlank String name,
    @NotBlank String description,
    @Nullable String specUri,
    @Nullable String documentationUri
) {
    /** RFC 7643 OAuth 1.0 authentication scheme type. */
    public static final String OAUTH = "oauth";
    /** RFC 7643 OAuth 2.0 authentication scheme type. */
    public static final String OAUTH_2 = "oauth2";
    /** RFC 7643 OAuth bearer token authentication scheme type. */
    public static final String OAUTH_BEARER_TOKEN = "oauthbearertoken";
    /** RFC 7643 HTTP Basic authentication scheme type. */
    public static final String HTTP_BASIC = "httpbasic";
    /** RFC 7643 HTTP Digest authentication scheme type. */
    public static final String HTTP_DIGEST = "httpdigest";
}
