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
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.Map;

/**
 * PublicKeyCredentialRequestOptions for WebAuthn authentication
 *
 * @param challenge A challenge to be signed by the authenticator
 * @param timeout Time (in milliseconds) that the caller is willing to wait for the call to complete
 * @param rpId Relying Party ID
 * @param allowCredentials List of acceptable credentials for authentication
 * @param userVerification User verification requirement
 * @param hints Hints for the browser about what types of authenticators to show
 * @param extensions WebAuthn extensions to enable
 * @since 5.5.1
 */
@Serdeable
@Experimental
public record CredentialRequestOptions(
    String challenge,
    @Nullable Integer timeout,
    @Nullable String rpId,
    @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
    @Nullable String userVerification,
    @Nullable List<String> hints,
    @Nullable Map<String, Object> extensions
) {
}
