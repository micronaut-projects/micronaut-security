/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * ID Token.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 * @author Sergio del Amo
 * @version 1.1.0
 */
public interface OpenIdClaims extends JwtClaims {

    String CLAIMS_NAME = "name";
    String CLAIMS_GIVEN_NAME = "given_name";
    String CLAIMS_FAMILY_NAME = "family_name";
    String CLAIMS_MIDDLE_NAME = "middle_name";
    String CLAIMS_NICKNAME = "nickname";
    String CLAIMS_PREFERRED_USERNAME = "preferred_username";
    String CLAIMS_PROFILE = "profile";
    String CLAIMS_PICTURE = "picture";
    String CLAIMS_WEBSITE = "website";
    String CLAIMS_EMAIL = "email";
    String CLAIMS_EMAIL_VERIFIED = "email_verified";
    String CLAIMS_GENDER = "gender";
    String CLAIMS_BIRTHDATE = "birthdate";
    String CLAIMS_ZONEINFO = "zoneinfo";
    String CLAIMS_LOCALE = "locale";
    String CLAIMS_PHONE_NUMBER = "phone_number";
    String CLAIMS_PHONE_NUMBER_VERIFIED = "phone_number_verified";
    String CLAIMS_ADDRESS = "address";
    String CLAIMS_UPDATED_AT = "updated_at";
    String CLAIMS_AUTH_TIME = "auth_time";
    String CLAIMS_NONCE = "nonce";
    String CLAIMS_ACR = "acr";
    String CLAIMS_AMR = "amr";
    String CLAIMS_AZP = "azp";

    /**
     *
     * @return The party to which the ID Token was issued.
     */
    @Nullable
    String getAuthorizedParty();

    /**
     *
     * @return Identifiers for authentication methods used in the authentication.
     */
    @Nullable
    List<String> getAuthenticationMethodReferences();

    /**
     *
     * @return Authentication Context Class Reference.
     */
    @Nullable
    String getAuthenticationContextClassReference();

    /**
     *
     * @return Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client,
     */
    @Nonnull
    String getIssuer();

    /**
     *
     * @return Audience(s) that this ID Token is intended for.
     */
    @Nonnull
    List<String> getAudience();

    /**
     *
     * @return Expiration time on or after which the ID Token MUST NOT be accepted for processing.
     */
    @Nonnull
    Date getExpirationTime();

    /**
     *
     * @return Time at which the JWT was issued.
     */
    @Nonnull
    Date getIssuedAt();

    /**
     * sub.
     * @return Identifier for the End-User at the Issuer.
     */
    @Nonnull
    String getSubject();

    /**
     *
     * @return Time when the End-User authentication occurred.
     */
    @Nullable
    Integer getAuthenticationTime();

    /**
     *
     * @return String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     */
    @Nullable
    String getNonce();

    /**
     * name.
     * @return End-User's full name in displayable form including all name parts, possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
     */
    @Nullable
    String getName();

    /**
     * given_name.
     * @return Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
     */
    @Nullable
    String getGivenName();

    /**
     * family_name.
     * @return Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
     */
    @Nullable
    String getFamilyName();

    /**
     * middle_name.
     * @return Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
     */
    @Nullable
    String getMiddleName();

    /**
     * nickname.
     * @return Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
     */
    @Nullable
    String getNickname();

    /**
     * preferred_username.
     * @return Shorthand name by which the End-User wishes to be referred to at the RP, such as janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
     */
    @Nullable
    String getPreferredUsername();

    /**
     * @return URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
     */
    @Nullable
    String getProfile();

    /**
     * @return URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
     */
    @Nullable
    String getPicture();

    /**
     * @return URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
     */
    @Nullable
    String getWebsite();

    /**
     * @return End-User's preferred e-mail address. Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
     */
    @Nullable
    String getEmail();

    /**
     * @return True if the End-User's e-mail address has been verified; otherwise false.
     */
    @Nullable
    Boolean isEmailVerified();

    /**
     *   @return End-User's gender. Values defined by this specification are female and male.
     *   Other values MAY be used when neither of the defined values are applicable.
     */
    @Nullable
    String getGender();

    /**
     * @return End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format.
     */
    @Nullable
    String getBirthday();

    /**
     * zoneinfo.
     * @return String from zoneinfo [zoneinfo] time zone database representing the End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
     */
    @Nullable
    String getZoneinfo();

    /**
     * @return End-User's locale, represented as a BCP47 [RFC5646] language tag.
     */
    @Nullable
    String getLocale();

    /**
     * @return End-User's preferred telephone number
     */
    @Nullable
    String getPhoneNumber();

    /**
     * @return True if the End-User's phone number has been verified; otherwise false.
     */
    @Nullable
    Boolean isPhoneNumberVerified();

    /**
     * address.
     * @return End-User's preferred postal address.
     */
    @Nullable
    Address getAdress();

    /**
     * @return Time the End-User's information was last updated.
     */
    @Nullable
    Integer getUpdatedAt();

    /**
     * @return ID token claims
     */
    Map<String, Object> getClaims();
}

