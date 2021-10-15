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
package io.micronaut.security.token.paseto.validators.sharedsecret;

import io.micronaut.context.annotation.EachProperty;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.paseto.config.PasetoConfigurationProperties;
import io.micronaut.security.token.paseto.config.SharedSecretConfiguration;
import jakarta.inject.Singleton;
import javax.crypto.SecretKey;
import javax.validation.constraints.NotNull;

/**
 * {@link EachProperty} implementation of {@link SharedSecretConfiguration}.
 */
@Singleton
@EachProperty(PasetoConfigurationProperties.PREFIX + ".shared-secret-validators")
public class SharedSecretConfigurationProperties implements SharedSecretConfiguration {

    @NonNull
    @NotNull
    private SecretKey sharedSecret;

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
        return sharedSecret;
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
     *
     * @param sharedSecret
     */
    public void setSharedSecret(@NonNull SecretKey sharedSecret) {
        this.sharedSecret = sharedSecret;
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
