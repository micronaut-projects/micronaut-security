/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.micronaut.security.token.paseto.validator.claims;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.paseto.config.PasetoConfigurationProperties;

/**
 * {@link ConfigurationProperties} implementation of {@link PasetoClaimsValidatorConfiguration}.
 *
 * @author Utsav Varia
 * @since 3.0
 */
@ConfigurationProperties(PasetoClaimsValidatorConfigurationProperties.PREFIX)
public class PasetoClaimsValidatorConfigurationProperties implements PasetoClaimsValidatorConfiguration {

    public static final String PREFIX = PasetoConfigurationProperties.PREFIX + ".claims-validators";

    /**
     * The default expiration value.
     */
    public static final boolean DEFAULT_EXPIRATION = true;

    /**
     * The default subject-not-null value.
     */
    public static final boolean DEFAULT_SUBJECT_NOT_NULL = true;

    /**
     * The default not-before value.
     */
    public static final boolean DEFAULT_NOT_BEFORE = false;

    @Nullable
    private String audience;

    @Nullable
    private String issuer;

    private boolean subjectNotNull = DEFAULT_SUBJECT_NOT_NULL;

    private boolean notBefore = DEFAULT_NOT_BEFORE;

    private boolean expiration = DEFAULT_EXPIRATION;

    @Override
    @Nullable
    public String getIssuer() {
        return issuer;
    }

    /**
     * @param issuer Whether the iss claim should be validated to ensure it matches this value. It defaults to null, thus it is not validated.
     */
    public void setIssuer(@Nullable String issuer) {
        this.issuer = issuer;
    }

    @Override
    @Nullable
    public String getAudience() {
        return audience;
    }

    /**
     * @param audience Whether the aud claim should be validated to ensure it matches this value. It defaults to null, thus it is not validated.
     */
    public void setAudience(@Nullable String audience) {
        this.audience = audience;
    }

    @Override
    public boolean isSubjectNotNull() {
        return subjectNotNull;
    }

    /**
     * @param subjectNotNull Whether the Paseto subject claim should be validated to ensure it is not null. Default value {@value #DEFAULT_SUBJECT_NOT_NULL}.
     */
    public void setSubjectNotNull(boolean subjectNotNull) {
        this.subjectNotNull = subjectNotNull;
    }

    /**
     * @return Whether it should be validated that validation time is not before the not-before claim (nbf) of a Paseto token.
     */
    @Override
    public boolean isNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore Whether it should be validated that validation time is not before the not-before claim (nbf) of a Paseto token. Default value {@value #DEFAULT_NOT_BEFORE}.
     */
    public void setNotBefore(boolean notBefore) {
        this.notBefore = notBefore;
    }

    @Override
    public boolean isExpiration() {
        return this.expiration;
    }

    /**
     * @param expiration Whether the expiration date of the Paseto should be validated. Default value {@value #DEFAULT_EXPIRATION}.
     */
    public void setExpiration(boolean expiration) {
        this.expiration = expiration;
    }

}
