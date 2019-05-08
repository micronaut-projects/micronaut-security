/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.token.response;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.core.util.functional.ThrowingFunction;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An implementation of {@link OpenIdClaims} backed by an {@link JWTClaimsSet}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class JWTOpenIdClaims implements OpenIdClaims {

    private final JWTClaimsSet claimsSet;

    /**
     * @param claimsSet The JWT claims set
     */
    public JWTOpenIdClaims(JWTClaimsSet claimsSet) {
        this.claimsSet = claimsSet;
    }

    @Nonnull
    @Override
    public String getIssuer() {
        return claimsSet.getIssuer();
    }

    @Nonnull
    @Override
    public List<String> getAudience() {
        return claimsSet.getAudience();
    }

    @Nonnull
    @Override
    public Date getExpirationTime() {
        return claimsSet.getExpirationTime();
    }

    @Nonnull
    @Override
    public Date getIssuedAt() {
        return claimsSet.getIssueTime();
    }

    @Nonnull
    @Override
    public String getSubject() {
        return claimsSet.getSubject();
    }

    @Nullable
    @Override
    public String getAuthorizedParty() {
        return getClaim(OpenIdClaims.CLAIMS_AZP, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public List<String> getAuthenticationMethodReferences() {
        return getClaim(OpenIdClaims.CLAIMS_AMR, claimsSet::getStringListClaim);
    }

    @Nullable
    @Override
    public String getAuthenticationContextClassReference() {
        return getClaim(OpenIdClaims.CLAIMS_ACR, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public Integer getAuthenticationTime() {
        return getClaim(OpenIdClaims.CLAIMS_AUTH_TIME, claimsSet::getIntegerClaim);
    }

    @Nullable
    @Override
    public String getNonce() {
        return getClaim(OpenIdClaims.CLAIMS_NONCE, claimsSet::getStringClaim);
    }

    @Override
    @Nullable
    public String getName() {
        return getClaim(OpenIdClaims.CLAIMS_NAME, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getGivenName() {
        return getClaim(OpenIdClaims.CLAIMS_GIVEN_NAME, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getFamilyName() {
        return getClaim(OpenIdClaims.CLAIMS_FAMILY_NAME, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getMiddleName() {
        return getClaim(OpenIdClaims.CLAIMS_MIDDLE_NAME, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getNickname() {
        return getClaim(OpenIdClaims.CLAIMS_NICKNAME, claimsSet::getStringClaim);
    }

    @Override
    @Nullable
    public String getPreferredUsername() {
        return getClaim(OpenIdClaims.CLAIMS_PREFERRED_USERNAME, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getProfile() {
        return getClaim(OpenIdClaims.CLAIMS_PROFILE, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getPicture() {
        return getClaim(OpenIdClaims.CLAIMS_PICTURE, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getWebsite() {
        return getClaim(OpenIdClaims.CLAIMS_WEBSITE, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getEmail() {
        return getClaim(OpenIdClaims.CLAIMS_EMAIL, claimsSet::getStringClaim);
    }

    @Override
    @Nullable
    public Boolean isEmailVerified() {
        return getClaim(OpenIdClaims.CLAIMS_EMAIL_VERIFIED, claimsSet::getBooleanClaim);
    }

    @Nullable
    @Override
    public String getGender() {
        return getClaim(OpenIdClaims.CLAIMS_GENDER, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getBirthday() {
        return getClaim(OpenIdClaims.CLAIMS_BIRTHDATE, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getZoneinfo() {
        return getClaim(OpenIdClaims.CLAIMS_ZONEINFO, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getLocale() {
        return getClaim(OpenIdClaims.CLAIMS_LOCALE, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public String getPhoneNumber() {
        return getClaim(OpenIdClaims.CLAIMS_PHONE_NUMBER, claimsSet::getStringClaim);
    }

    @Nullable
    @Override
    public Boolean isPhoneNumberVerified() {
        return getClaim(OpenIdClaims.CLAIMS_PHONE_NUMBER_VERIFIED, claimsSet::getBooleanClaim);
    }

    @Nullable
    @Override
    public Address getAdress() {
        Object addressClaim = claimsSet.getClaim(OpenIdClaims.CLAIMS_ADDRESS);
        if (addressClaim instanceof Address) {
            return (Address) addressClaim;
        } else if (addressClaim instanceof Map) {
            return new Address((Map<String, Object>) addressClaim);
        } else {
            return null;
        }
    }

    @Nullable
    @Override
    public Integer getUpdatedAt() {
        return getClaim(OpenIdClaims.CLAIMS_UPDATED_AT, claimsSet::getIntegerClaim);
    }

    @Override
    public Map<String, Object> getClaims() {
        return claimsSet.getClaims();
    }

    private <R> R getClaim(String claim, ThrowingFunction<String, R, ParseException> function) {
        try {
            return function.apply(claim);
        } catch (ParseException e) {
            return null;
        }
    }

    @Nullable
    @Override
    public Object get(String claimName) {
        return claimsSet.getClaim(claimName);
    }

    @Nonnull
    @Override
    public Set<String> names() {
        return claimsSet.getClaims().keySet();
    }

    @Override
    public boolean contains(String claimName) {
        return claimsSet.getClaims().containsKey(claimName);
    }
}
