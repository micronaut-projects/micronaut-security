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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.Introspected;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * Represents the response of an authorization server to an invalid access token request, with the error code as a
 * string. Unlike {@link TokenErrorResponse}, whose error is the {@link TokenError} enum of the codes RFC 6749
 * section 5.2 defines, it also carries the error codes providers add to those of the specification.
 *
 * <p>The error description is free text written by the provider. Log the error code, not the whole record.</p>
 *
 * <p>Internal: it only serves {@link ThrowableAuthenticationResponseAdapter} to read the error code of a rejected
 * password grant. {@link TokenErrorResponse} remains the public representation of a token error response.</p>
 *
 * @param error The error code
 * @param errorDescription The error description
 * @param errorUri The error uri
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC 6749 Access Token Error Response</a>
 *
 * @author Sergio del Amo
 * @since 5.5.2
 */
@Internal
@Introspected
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record GenericTokenErrorResponse(@NonNull String error,
                                        @Nullable String errorDescription,
                                        @Nullable String errorUri) {
}
