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
package io.micronaut.supabase.auth;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Map;

/**
 * WebAuthn {@code PublicKeyCredentialRequestOptions} issued when a WebAuthn factor is challenged.
 *
 * <p>Pass these options to the browser's {@code navigator.credentials.get()} call and return the
 * resulting assertion through the factor verification request.</p>
 *
 * @param challenge Random challenge the authenticator must sign, base64url encoded
 * @param timeout Milliseconds the caller is willing to wait for the ceremony to complete
 * @param rpId Relying party identifier the credential must be scoped to
 * @param allowCredentials Credentials acceptable for this authentication; empty allows any discoverable credential
 * @param userVerification User verification requirement: {@code discouraged}, {@code preferred} or {@code required}
 * @param hints Hints about which kinds of authenticator the browser should offer
 * @param extensions WebAuthn extensions to enable, keyed by extension identifier
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record CredentialRequestOptions(
    @NotBlank String challenge,
    @Nullable Integer timeout,
    @Nullable String rpId,
    @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
    @Nullable String userVerification,
    @Nullable List<String> hints,
    @Nullable Map<String, Object> extensions
) {
}
