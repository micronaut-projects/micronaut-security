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
package io.micronaut.security.token;

import java.util.Set;

/**
 * Constants for the <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Standard Claims</a>.
 * These are the member names of the standard set of claims about the authenticated end-user that may be returned in the ID Token
 * and/or by the UserInfo Endpoint.
 *
 * @author Sergio del Amo
 * @since 5.3.0
 */
public final class ProfileClaims {

    /**
     * Subject - Identifier for the end-user at the issuer.
     */
    public static final String CLAIM_SUB = "sub";

    /**
     * End-user's full name in displayable form including all name parts, possibly including titles and suffixes,
     * ordered according to the end-user's locale and preferences.
     */
    public static final String CLAIM_NAME = "name";

    /**
     * Given name(s) or first name(s) of the end-user. Note that in some cultures, people can have multiple given names;
     * all can be present, with the names being separated by space characters.
     */
    public static final String CLAIM_GIVEN_NAME = "given_name";

    /**
     * Surname(s) or last name(s) of the end-user. Note that in some cultures, people can have multiple family names or no
     * family name; all can be present, with the names being separated by space characters.
     */
    public static final String CLAIM_FAMILY_NAME = "family_name";

    /**
     * Middle name(s) of the end-user. Note that in some cultures, people can have multiple middle names; all can be present,
     * with the names being separated by space characters. Also note that in some cultures, middle names are not used.
     */
    public static final String CLAIM_MIDDLE_NAME = "middle_name";

    /**
     * Casual name of the end-user that may or may not be the same as the given_name. For instance, a nickname value of
     * Mike might be returned alongside a given_name value of Michael.
     */
    public static final String CLAIM_NICKNAME = "nickname";

    /**
     * Shorthand name by which the end-user wishes to be referred to at the relying party, such as janedoe or j.doe.
     * This value may be any valid JSON string including special characters such as {@code @}, {@code /}, or whitespace.
     */
    public static final String CLAIM_PREFERRED_USERNAME = "preferred_username";

    /**
     * URL of the end-user's profile page. The contents of this web page should be about the end-user.
     */
    public static final String CLAIM_PROFILE = "profile";

    /**
     * URL of the end-user's profile picture. This URL must refer to an image file (for example, a PNG, JPEG, or GIF image
     * file), rather than to a web page containing an image.
     */
    public static final String CLAIM_PICTURE = "picture";

    /**
     * URL of the end-user's web page or blog. This web page should contain information published by the end-user or an
     * organization that the end-user is affiliated with.
     */
    public static final String CLAIM_WEBSITE = "website";

    /**
     * End-user's preferred e-mail address. Its value must conform to the RFC 5322 addr-spec syntax.
     */
    public static final String CLAIM_EMAIL = "email";

    /**
     * True if the end-user's e-mail address has been verified; otherwise false. When this claim value is true, this means
     * that the OpenID Provider took affirmative steps to ensure that this e-mail address was controlled by the end-user
     * at the time the verification was performed.
     */
    public static final String CLAIM_EMAIL_VERIFIED = "email_verified";

    /**
     * End-user's gender. Values defined by this specification are female and male. Other values may be used when neither
     * of the defined values are applicable.
     */
    public static final String CLAIM_GENDER = "gender";

    /**
     * End-user's birthday, represented as an ISO 8601-1 YYYY-MM-DD format. The year may be 0000, indicating that it is
     * omitted. To represent only the year, YYYY format is allowed.
     */
    public static final String CLAIM_BIRTHDATE = "birthdate";

    /**
     * String from IANA Time Zone Database representing the end-user's time zone. For example, Europe/Paris or
     * America/Los_Angeles.
     */
    public static final String CLAIM_ZONEINFO = "zoneinfo";

    /**
     * End-user's locale, represented as a BCP47 language tag. This is typically an ISO 639 Alpha-2 language code in
     * lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, en-US or fr-CA.
     */
    public static final String CLAIM_LOCALE = "locale";

    /**
     * End-user's preferred telephone number. E.164 is recommended as the format of this claim, for example, +1 (425)
     * 555-1212 or +56 (2) 687 2400.
     */
    public static final String CLAIM_PHONE_NUMBER = "phone_number";

    /**
     * True if the end-user's phone number has been verified; otherwise false. When this claim value is true, this means
     * that the OpenID Provider took affirmative steps to ensure that this phone number was controlled by the end-user at
     * the time the verification was performed.
     */
    public static final String CLAIM_PHONE_NUMBER_VERIFIED = "phone_number_verified";

    /**
     * End-user's preferred postal address. The value of the address member is a JSON structure containing some or all of
     * the members defined in the OpenID Connect Address Claim.
     */
    public static final String CLAIM_ADDRESS = "address";

    /**
     * Time the end-user's information was last updated. Its value is a JSON number representing the number of seconds from
     * 1970-01-01T00:00:00Z as measured in UTC until the date/time.
     */
    public static final String CLAIM_UPDATED_AT = "updated_at";

    private ProfileClaims() {
    }

    public static Set<String> all() {
        return Set.of(CLAIM_SUB,
                CLAIM_NAME,
                CLAIM_GIVEN_NAME,
                CLAIM_FAMILY_NAME,
                CLAIM_MIDDLE_NAME,
                CLAIM_NICKNAME,
                CLAIM_PREFERRED_USERNAME,
                CLAIM_PROFILE,
                CLAIM_PICTURE,
                CLAIM_WEBSITE,
                CLAIM_EMAIL,
                CLAIM_EMAIL_VERIFIED,
                CLAIM_GENDER,
                CLAIM_BIRTHDATE,
                CLAIM_ZONEINFO,
                CLAIM_LOCALE,
                CLAIM_PHONE_NUMBER,
                CLAIM_PHONE_NUMBER_VERIFIED,
                CLAIM_ADDRESS,
                CLAIM_UPDATED_AT);
    }
}
