/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.config;

import io.micronaut.context.annotation.EachProperty;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import jakarta.inject.Singleton;

import javax.crypto.SecretKey;
import javax.validation.constraints.NotNull;

/**
 * {@link EachProperty} implementation of {@link SharedSecretConfiguration}.
 */
@Singleton
@EachProperty(PasetoConfigurationProperties.PREFIX + ".local-validators")
public class LocalValidators implements SharedSecretConfiguration {

    @NonNull
    @NotNull
    private SecretKey base64SharedSecret;

    @Nullable
    private String requiredAudience;

    @Nullable
    private String requiredKeyId;

    @Nullable
    private String requiredIssuer;

    @Nullable
    private String requiredSubject;

    @Nullable
    private String requiredTokenId;

    @Override
    @NonNull
    public SecretKey getSharedSecret() {
        return base64SharedSecret;
    }

    @Nullable
    @Override
    public String getRequiredAudience() {
        return this.requiredAudience;
    }

    @Override
    @Nullable
    public String getRequiredKeyId() {
        return requiredKeyId;
    }

    @Override
    @Nullable
    public String getRequiredIssuer() {
        return requiredIssuer;
    }

    @Override
    @Nullable
    public String getRequiredSubject() {
        return requiredSubject;
    }

    @Override
    @Nullable
    public String getRequiredTokenId() {
        return requiredTokenId;
    }

    /**
     * The required value for the required token id.
     * @param requiredTokenId The required value for the token id
     */
    public void setRequiredTokenId(@Nullable String requiredTokenId) {
        this.requiredTokenId = requiredTokenId;
    }

    /**
     * Shared Secret.
     * @param base64SharedSecret Shared Secret
     */
    public void setBase64SharedSecret(@NonNull SecretKey base64SharedSecret) {
        this.base64SharedSecret = base64SharedSecret;
    }

    /**
     * The required value for the audience claim.
     * @param requiredAudience The required value for the audience claim.
     */
    public void setRequiredAudience(@Nullable String requiredAudience) {
        this.requiredAudience = requiredAudience;
    }

    /**
     * The required value for the keyId.
     * @param requiredKeyId The required value of the keyId
     */
    public void setRequiredKeyId(@Nullable String requiredKeyId) {
        this.requiredKeyId = requiredKeyId;
    }

    /**
     * The required issuer value.
     * @param requiredIssuer The required issuer value
     */
    public void setRequiredIssuer(@Nullable String requiredIssuer) {
        this.requiredIssuer = requiredIssuer;
    }

    /**
     * The required subject value.
     * @param requiredSubject The required subject value
     */
    public void setRequiredSubject(@Nullable String requiredSubject) {
        this.requiredSubject = requiredSubject;
    }

}
