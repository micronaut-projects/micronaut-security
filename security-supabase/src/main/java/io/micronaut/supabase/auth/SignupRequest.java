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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Raw JSON body accepted by Supabase Auth's {@code POST /signup} endpoint.
 *
 * <p>Provide either an email address or a phone number with a password. The
 * redirect URL is a query parameter on the client method, not part of this
 * JSON body.</p>
 *
 * @param email Email signup address
 * @param phone Phone signup number
 * @param password User password
 * @param channel Phone verification channel, such as {@code sms} or {@code whatsapp}
 * @param data User metadata to attach at signup
 * @param codeChallenge PKCE code challenge
 * @param codeChallengeMethod PKCE method, either {@code s256} or {@code plain}
 * @param security CAPTCHA token data
 */
@Serdeable
@Experimental
public record SignupRequest(
    @Nullable String email,
    @Nullable String phone,
    @NonNull String password,
    @Nullable String channel,
    @Nullable Map<String, Object> data,
    @JsonProperty("code_challenge") @Nullable String codeChallenge,
    @JsonProperty("code_challenge_method") @Nullable String codeChallengeMethod,
    @JsonProperty("gotrue_meta_security") @Nullable Security security
) {
    /**
     * CAPTCHA fields accepted by GoTrue.
     *
     * @param captchaToken Verification token from the CAPTCHA provider
     */
    @Serdeable
    public record Security(
        @JsonProperty("captcha_token") @Nullable String captchaToken
    ) {
    }
}
