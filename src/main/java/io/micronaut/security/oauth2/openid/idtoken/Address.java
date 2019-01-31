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

package io.micronaut.security.oauth2.openid.idtoken;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.annotation.Nullable;

/**
 * Representation of an Address Claim which represents a physical mailing address.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">Address Claim</a>.
 *
 * @author Sergio del Amo
 * @version 1.1.0
 */
public class Address {

    public static final String JSONKEY_COUNTRY = "country";
    public static final String JSONKEY_STREET_ADDRESS = "street_address";
    public static final String JSONKEY_LOCALITY = "locality";
    public static final String JSONKEY_POSTAL_CODE = "postal_code";
    public static final String JSONKEY_REGION = "region";

    @Nullable
    private String formatted;

    @Nullable
    @JsonProperty(JSONKEY_STREET_ADDRESS)
    private String streetAddress;

    @Nullable
    private String locality;

    @Nullable
    private String region;

    @Nullable
    @JsonProperty(JSONKEY_POSTAL_CODE)
    private String postalCode;

    private String country;

    /**
     * Address Claim constructor.
     */
    public Address() {

    }

    /**
     *
     * @return Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information.
     */
    @Nullable
    public String getStreetAddress() {
        return streetAddress;
    }

    /**
     * Sets the full street address.
     * @param streetAddress Street address.
     */
    public void setStreetAddress(@Nullable String streetAddress) {
        this.streetAddress = streetAddress;
    }

    /**
     *
     * @return City or locality component.
     */
    @Nullable
    public String getLocality() {
        return locality;
    }

    /**
     * Address's locality.
     * @param locality Locality
     */
    public void setLocality(@Nullable String locality) {
        this.locality = locality;
    }

    /**
     * @return State, province, prefecture or region component.
     */
    @Nullable
    public String getRegion() {
        return region;
    }

    /**
     * Address' region.
     * @param region Region.
     */
    public void setRegion(@Nullable String region) {
        this.region = region;
    }

    /**
     *
     * @return Zip code or postal code component.
     */
    @Nullable
    public String getPostalCode() {
        return postalCode;
    }

    /**
     * Address's postal code.
     * @param postalCode Postal code.
     */
    public void setPostalCode(@Nullable String postalCode) {
        this.postalCode = postalCode;
    }

    /**
     *
     * @return Country name component.
     */
    @Nullable
    public String getCountry() {
        return country;
    }

    /**
     * Address's country.
     * @param country country.
     */
    public void setCountry(@Nullable String country) {
        this.country = country;
    }

    /**
     *
     * @return Full mailing address, formatted for display or use on a mailing label.
     */
    @Nullable
    public String getFormatted() {
        return formatted;
    }

    /**
     *
     * @param formatted Full mailing address, formatted for display or use on a mailing label.
     */
    public void setFormatted(@Nullable String formatted) {
        this.formatted = formatted;
    }
}
