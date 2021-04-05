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
package io.micronaut.security.token.jwt.validator;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

/**
 * {@link ConfigurationProperties} implementation of {@link JwtClaimsValidatorConfiguration}.
 *
 * @author Sergio del Amo
 * @since 2.4.0
 */
@ConfigurationProperties(JwtClaimsValidatorConfigurationProperties.PREFIX)
public class JwtClaimsValidatorConfigurationProperties implements JwtClaimsValidatorConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".claims-validators";

    /**
     * The default nonce value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_NONCE = true;

    /**
     * The default expiration value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_EXPIRATION = true;

    /**
     * The default subject-not-null value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_SUBJECT_NOT_NULL = true;

    /**
     * The default not-before value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_NOT_BEFORE = false;

    /**
     * The default not-before value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_OPENID_ID_TOKEN = true;

    private boolean nonce = DEFAULT_NONCE;

    @Nullable
    private String audience;

    @Nullable
    private String issuer;

    private boolean subjectNotNull = DEFAULT_SUBJECT_NOT_NULL;

    private boolean notBefore = DEFAULT_NOT_BEFORE;

    private boolean expiration = DEFAULT_EXPIRATION;

    private boolean openidIdtoken = DEFAULT_OPENID_ID_TOKEN;

    @Override
    @Nullable
    public String getIssuer() {
        return issuer;
    }

    /**
     *
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
     *
     * @param  audience Whether the aud claim should be validated to ensure it matches this value. It defaults to null, thus it is not validated.
     */
    public void setAudience(@Nullable String audience) {
        this.audience = audience;
    }

    @Override
    public boolean isSubjectNotNull() {
        return subjectNotNull;
    }

    /**
     *
     * @param subjectNotNull Whether the JWT subject claim should be validated to ensure it is not null. Default value {@value #DEFAULT_SUBJECT_NOT_NULL}.
     */
    public void setSubjectNotNull(boolean subjectNotNull) {
        this.subjectNotNull = subjectNotNull;
    }

    /**
     *
     * @return Whether it should be validated that validation time is not before the not-before claim (nbf) of a JWT token.
     */
    @Override
    public boolean isNotBefore() {
        return notBefore;
    }

    /**
     *
     * @param notBefore Whether it should be validated that validation time is not before the not-before claim (nbf) of a JWT token. Default value {@value #DEFAULT_NOT_BEFORE}.
     */
    public void setNotBefore(boolean notBefore) {
        this.notBefore = notBefore;
    }

    @Override
    public boolean isExpiration() {
        return this.expiration;
    }

    /**
     *
     * @param expiration Whether the expiration date of the JWT should be validated. Default value {@value #DEFAULT_EXPIRATION}.
     */
    public void setExpiration(boolean expiration) {
        this.expiration = expiration;
    }

    @Override
    public boolean isNonce() {
        return nonce;
    }

    /**
     *
     * @param nonce Whether the nonce claim should be validated when a nonce was present. Default value {@value #DEFAULT_NONCE}.
     */
    public void setNonce(boolean nonce) {
        this.nonce = nonce;
    }

    @Override
    public boolean isOpenidIdtoken() {
        return openidIdtoken;
    }

    /**
     * @param openidIdtoken Whether `IdTokenClaimsValidator`, which performs some fo the verifications described in OpenID Connect Spec, is enabled. Default value {@value #DEFAULT_OPENID_ID_TOKEN}. Only applies for `idtoken` authentication mode.
     */
    public void setOpenidIdtoken(boolean openidIdtoken) {
        this.openidIdtoken = openidIdtoken;
    }
}
