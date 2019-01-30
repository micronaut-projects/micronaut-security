/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.openid.idtoken;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.micronaut.security.oauth2.openid.idtoken.Address.JSONKEY_COUNTRY;
import static io.micronaut.security.oauth2.openid.idtoken.Address.JSONKEY_LOCALITY;
import static io.micronaut.security.oauth2.openid.idtoken.Address.JSONKEY_POSTAL_CODE;
import static io.micronaut.security.oauth2.openid.idtoken.Address.JSONKEY_REGION;
import static io.micronaut.security.oauth2.openid.idtoken.Address.JSONKEY_STREET_ADDRESS;

/**
 * Adapts from {@link Authentication} to {@link IdToken}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class IdTokenAuthenticationAdapter implements IdToken {

    private final Authentication authentication;

    /**
     * Constructs an adapter between {@link Authentication} to {@link IdToken}.
     *
     * @param authentication Authentication's state representation.
     */
    public IdTokenAuthenticationAdapter(Authentication authentication) {
        this.authentication = authentication;
    }

    @Nullable
    @Override
    public String getAuthorizedParty() {
        return getStringValue(IdToken.CLAIMS_AZP);
    }

    @Nullable
    @Override
    public List<String> getAuthenticationMethodReferences() {
        return getListOfStringsValue(IdToken.CLAIMS_AMR);
    }

    @Nullable
    @Override
    public String getAuthenticationContextClassReference() {
        return getStringValue(IdToken.CLAIMS_ACR);
    }

    @Nonnull
    @Override
    public String getIssuer() {
        return getStringValue(JwtClaims.ISSUER);
    }

    @Nonnull
    @Override
    public String getAudience() {
        return getStringValue(JwtClaims.AUDIENCE);
    }

    @Nonnull
    @Override
    public Integer getExpirationTime() {
        return getIntegerValue(JwtClaims.EXPIRATION_TIME);
    }

    @Nonnull
    @Override
    public Integer getIssuedAt() {
        return getIntegerValue(JwtClaims.ISSUED_AT);
    }

    @Nonnull
    @Override
    public String getSubject() {
        return getStringValue(JwtClaims.SUBJECT);
    }

    @Nullable
    @Override
    public Integer getAuthenticationTime() {
        return getIntegerValue(IdToken.CLAIMS_AUTH_TIME);
    }

    @Nullable
    @Override
    public String getNonce() {
        return getStringValue(IdToken.CLAIMS_NONCE);
    }

    @Override
    @Nullable
    public String getName() {
        return getStringValue(IdToken.CLAIMS_NAME);
    }

    @Nullable
    @Override
    public String getGivenName() {
        return getStringValue(IdToken.CLAIMS_GIVEN_NAME);
    }

    @Nullable
    @Override
    public String getFamilyName() {
        return getStringValue(IdToken.CLAIMS_FAMILY_NAME);
    }

    @Nullable
    @Override
    public String getMiddleName() {
        return getStringValue(IdToken.CLAIMS_MIDDLE_NAME);
    }

    @Nullable
    @Override
    public String getNickname() {
        return getStringValue(IdToken.CLAIMS_NICKNAME);
    }

    @Override
    @Nullable
    public String getPreferredUsername() {
        return getStringValue(IdToken.CLAIMS_PREFERRED_USERNAME);
    }

    @Nullable
    @Override
    public String getProfile() {
        return getStringValue(IdToken.CLAIMS_PROFILE);
    }

    @Nullable
    @Override
    public String getPicture() {
        return getStringValue(IdToken.CLAIMS_PICTURE);
    }

    @Nullable
    @Override
    public String getWebsite() {
        return getStringValue(IdToken.CLAIMS_WEBSITE);
    }

    @Nullable
    @Override
    public String getEmail() {
        return getStringValue(IdToken.CLAIMS_EMAIL);
    }

    @Override
    @Nullable
    public Boolean isEmailVerified() {
        return getBooleanValue(IdToken.CLAIMS_EMAIL_VERIFIED);
    }

    @Nullable
    @Override
    public String getGender() {
        return getStringValue(IdToken.CLAIMS_GENDER);
    }

    @Nullable
    @Override
    public String getBirthday() {
        return getStringValue(IdToken.CLAIMS_BIRTHDATE);
    }

    @Nullable
    @Override
    public String getZoneinfo() {
        return getStringValue(IdToken.CLAIMS_ZONEINFO);
    }

    @Nullable
    @Override
    public String getLocale() {
        return getStringValue(IdToken.CLAIMS_LOCALE);
    }

    @Nullable
    @Override
    public String getPhoneNumber() {
        return getStringValue(IdToken.CLAIMS_PHONE_NUMBER);
    }

    @Nullable
    @Override
    public Boolean isPhoneNumberVerified() {
        return getBooleanValue(IdToken.CLAIMS_PHONE_NUMBER_VERIFIED);
    }

    @Nullable
    @Override
    public Address getAdress() {
        return getAddressValue(IdToken.CLAIMS_ADDRESS);
    }

    @Nullable
    @Override
    public Integer getUpdatedAt() {
        return getIntegerValue(IdToken.CLAIMS_UPDATED_AT);
    }

    @Override
    public Map<String, Object> getClaims() {
        return authentication.getAttributes();
    }

    private String getStringValue(String claim) {
        if (authentication.getAttributes() != null && authentication.getAttributes().containsKey(claim)) {
            Object value = authentication.getAttributes().get(claim);
            if (value instanceof String) {
                return (String) value;
            }
        }
        return null;
    }

    private Boolean getBooleanValue(String claim) {
        if (authentication.getAttributes() != null && authentication.getAttributes().containsKey(claim)) {
            Object value = authentication.getAttributes().get(claim);
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
        }
        return null;
    }

    private Integer getIntegerValue(String claim) {
        if (authentication.getAttributes() != null && authentication.getAttributes().containsKey(claim)) {
            Object value = authentication.getAttributes().get(claim);
            if (value instanceof Integer) {
                return (Integer) value;
            }
        }
        return null;
    }

    private Address getAddressValue(String claim) {
        if (authentication.getAttributes() != null && authentication.getAttributes().containsKey(claim)) {
            Object value = authentication.getAttributes().get(claim);
            if (value instanceof Map) {
                Map m = (Map) value;
                return instantiateAddressFromMap(m);
            } else if (value instanceof Address) {
                return (Address) value;
            }
        }
        return null;
    }

    /**
     *
     * @param m Map with built from a JSON payload
     * @return An {@link Address} which represents an Address Claim.
     */
    protected Address instantiateAddressFromMap(Map m) {
        Address address = new Address();
        String country = stringValueAtKey(m, JSONKEY_COUNTRY);
        if (country != null) {
            address.setCountry(country);
        }
        String streetAddress = stringValueAtKey(m, JSONKEY_STREET_ADDRESS);
        if (streetAddress != null) {
            address.setStreetAddress(streetAddress);
        }
        String locality = stringValueAtKey(m, JSONKEY_LOCALITY);
        if (locality != null) {
            address.setLocality(locality);
        }
        String postalCode = stringValueAtKey(m, JSONKEY_POSTAL_CODE);
        if (postalCode != null) {
            address.setPostalCode(postalCode);
        }
        String region = stringValueAtKey(m, JSONKEY_REGION);
        if (region != null) {
            address.setPostalCode(region);
        }
        return address;
    }

    private String stringValueAtKey(Map m, String keyName) {
        if (m.containsKey(keyName)) {
            Object countryObj = m.get(keyName);
            if (countryObj instanceof String) {
                return (String) countryObj;
            }
        }
        return null;
    }

    private List<String> getListOfStringsValue(String claim) {
        if (authentication.getAttributes() != null && authentication.getAttributes().containsKey(claim)) {
            Object value = authentication.getAttributes().get(claim);
            if (value instanceof List) {
                List<String> result = new ArrayList<>();
                for (Object item : (List) value) {
                    if (item instanceof String) {
                        result.add((String) item);
                    }
                }
                return result;
            }
        }
        return null;
    }

}
