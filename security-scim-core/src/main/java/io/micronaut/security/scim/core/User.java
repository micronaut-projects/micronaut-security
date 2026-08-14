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
package io.micronaut.security.scim.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7643 User resource.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public final class User extends ScimResource {
    @Nullable
    @NotBlank
    private String userName;
    @Nullable
    @Valid
    private Name name;
    @Nullable
    private String displayName;
    @Nullable
    private String nickName;
    @Nullable
    private String profileUrl;
    @Nullable
    private String title;
    @Nullable
    private String userType;
    @Nullable
    private String preferredLanguage;
    @Nullable
    private String locale;
    @Nullable
    private String timezone;
    @Nullable
    private Boolean active;
    @Nullable
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    @Nullable
    private List<@Valid MultiValuedAttribute> emails;
    @Nullable
    private List<@Valid MultiValuedAttribute> phoneNumbers;
    @Nullable
    private List<@Valid MultiValuedAttribute> ims;
    @Nullable
    private List<@Valid MultiValuedAttribute> photos;
    @Nullable
    private List<@Valid Address> addresses;
    @Nullable
    private List<@Valid ResourceReference> groups;
    @Nullable
    private List<@Valid MultiValuedAttribute> entitlements;
    @Nullable
    private List<@Valid MultiValuedAttribute> roles;
    @Nullable
    private List<@Valid MultiValuedAttribute> x509Certificates;
    @Nullable
    @Valid
    private EnterpriseUser enterpriseUser;

    /**
     * Creates a User with the RFC 7643 User schema URI.
     *
     * @since 5.4.0
     */
    public User() {
        super(SchemaUris.USER);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The service-provider-unique user name
     * @since 5.4.0
     */
    @Nullable
    public String getUserName() {
        return userName;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param userName The service-provider-unique user name
     * @since 5.4.0
     */
    public void setUserName(@Nullable String userName) {
        this.userName = userName;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The components of the User's name
     * @since 5.4.0
     */
    @Nullable
    public Name getName() {
        return name;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param name The components of the User's name
     * @since 5.4.0
     */
    public void setName(@Nullable Name name) {
        this.name = name;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's primary display label
     * @since 5.4.0
     */
    @Nullable
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param displayName The User's primary display label
     * @since 5.4.0
     */
    public void setDisplayName(@Nullable String displayName) {
        this.displayName = displayName;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The casual name used to address the User
     * @since 5.4.0
     */
    @Nullable
    public String getNickName() {
        return nickName;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param nickName The casual name used to address the User
     * @since 5.4.0
     */
    public void setNickName(@Nullable String nickName) {
        this.nickName = nickName;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The URI of the User's online profile
     * @since 5.4.0
     */
    @Nullable
    public String getProfileUrl() {
        return profileUrl;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param profileUrl The URI of the User's online profile
     * @since 5.4.0
     */
    public void setProfileUrl(@Nullable String profileUrl) {
        this.profileUrl = profileUrl;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's title
     * @since 5.4.0
     */
    @Nullable
    public String getTitle() {
        return title;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param title The User's title
     * @since 5.4.0
     */
    public void setTitle(@Nullable String title) {
        this.title = title;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's relationship to the organization
     * @since 5.4.0
     */
    @Nullable
    public String getUserType() {
        return userType;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param userType The User's relationship to the organization
     * @since 5.4.0
     */
    public void setUserType(@Nullable String userType) {
        this.userType = userType;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's Accept-Language formatted language preference
     * @since 5.4.0
     */
    @Nullable
    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param preferredLanguage The User's Accept-Language formatted language preference
     * @since 5.4.0
     */
    public void setPreferredLanguage(@Nullable String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's default locale
     * @since 5.4.0
     */
    @Nullable
    public String getLocale() {
        return locale;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param locale The User's default locale
     * @since 5.4.0
     */
    public void setLocale(@Nullable String locale) {
        this.locale = locale;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's time zone name
     * @since 5.4.0
     */
    @Nullable
    public String getTimezone() {
        return timezone;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param timezone The User's time zone name
     * @since 5.4.0
     */
    public void setTimezone(@Nullable String timezone) {
        this.timezone = timezone;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's administrative status
     * @since 5.4.0
     */
    @Nullable
    public Boolean getActive() {
        return active;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param active The User's administrative status
     * @since 5.4.0
     */
    public void setActive(@Nullable Boolean active) {
        this.active = active;
    }

    /**
     * Returns the write-only password value. JSON serialization never emits this value.
     *
     * @return The password supplied by a client
     * @since 5.4.0
     */
    @Nullable
    public String getPassword() {
        return password;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param password A password to set, replace, or compare
     * @since 5.4.0
     */
    public void setPassword(@Nullable String password) {
        this.password = password;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's email addresses
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getEmails() {
        return emails;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param emails The User's email addresses
     * @since 5.4.0
     */
    public void setEmails(@Nullable List<MultiValuedAttribute> emails) {
        this.emails = emails;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's phone numbers
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getPhoneNumbers() {
        return phoneNumbers;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param phoneNumbers The User's phone numbers
     * @since 5.4.0
     */
    public void setPhoneNumbers(@Nullable List<MultiValuedAttribute> phoneNumbers) {
        this.phoneNumbers = phoneNumbers;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's instant messaging addresses
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getIms() {
        return ims;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param ims The User's instant messaging addresses
     * @since 5.4.0
     */
    public void setIms(@Nullable List<MultiValuedAttribute> ims) {
        this.ims = ims;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's photos
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getPhotos() {
        return photos;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param photos The User's photos
     * @since 5.4.0
     */
    public void setPhotos(@Nullable List<MultiValuedAttribute> photos) {
        this.photos = photos;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's physical mailing addresses
     * @since 5.4.0
     */
    @Nullable
    public List<Address> getAddresses() {
        return addresses;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param addresses The User's physical mailing addresses
     * @since 5.4.0
     */
    public void setAddresses(@Nullable List<Address> addresses) {
        this.addresses = addresses;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The groups to which the User belongs
     * @since 5.4.0
     */
    @Nullable
    public List<ResourceReference> getGroups() {
        return groups;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param groups The groups to which the User belongs
     * @since 5.4.0
     */
    public void setGroups(@Nullable List<ResourceReference> groups) {
        this.groups = groups;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's entitlements
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getEntitlements() {
        return entitlements;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param entitlements The User's entitlements
     * @since 5.4.0
     */
    public void setEntitlements(@Nullable List<MultiValuedAttribute> entitlements) {
        this.entitlements = entitlements;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's roles
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getRoles() {
        return roles;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param roles The User's roles
     * @since 5.4.0
     */
    public void setRoles(@Nullable List<MultiValuedAttribute> roles) {
        this.roles = roles;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The User's base64-encoded DER X.509 certificates
     * @since 5.4.0
     */
    @Nullable
    public List<MultiValuedAttribute> getX509Certificates() {
        return x509Certificates;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param x509Certificates The User's base64-encoded DER X.509 certificates
     * @since 5.4.0
     */
    public void setX509Certificates(@Nullable List<MultiValuedAttribute> x509Certificates) {
        this.x509Certificates = x509Certificates;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The standard enterprise User extension
     * @since 5.4.0
     */
    @Nullable
    @JsonProperty(SchemaUris.ENTERPRISE_USER)
    public EnterpriseUser getEnterpriseUser() {
        return enterpriseUser;
    }

    /**
     * Sets the enterprise extension and keeps the {@code schemas} attribute synchronized.
     *
     * @param enterpriseUser The standard enterprise User extension
     * @since 5.4.0
     */
    @JsonProperty(SchemaUris.ENTERPRISE_USER)
    public void setEnterpriseUser(@Nullable EnterpriseUser enterpriseUser) {
        this.enterpriseUser = enterpriseUser;
        if (enterpriseUser == null) {
            removeSchema(SchemaUris.ENTERPRISE_USER);
        } else {
            addSchema(SchemaUris.ENTERPRISE_USER);
        }
    }
}
