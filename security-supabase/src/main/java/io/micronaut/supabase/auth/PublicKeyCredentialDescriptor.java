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

/**
 * WebAuthn {@code PublicKeyCredentialDescriptor} identifying an existing credential.
 *
 * <p>Used in {@link CredentialCreationOptions#excludeCredentials()} to avoid re-registering a credential
 * and in {@link CredentialRequestOptions#allowCredentials()} to restrict which credentials may authenticate.</p>
 *
 * @param type Credential type; currently always {@code public-key}
 * @param id Credential identifier, base64url encoded
 * @param transports Transports the authenticator supports, such as {@code usb}, {@code nfc}, {@code ble} or
 *                   {@code internal}
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record PublicKeyCredentialDescriptor(
    @NotBlank String type,
    @NotBlank String id,
    @Nullable List<String> transports
) {
}
