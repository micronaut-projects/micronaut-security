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

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7643 service-provider configuration discovery resource.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public final class ServiceProviderConfig extends ScimResource {
    @Nullable
    private String documentationUri;
    @Nullable
    @NotNull
    @Valid
    private SupportedFeature patch;
    @Nullable
    @NotNull
    @Valid
    private BulkFeature bulk;
    @Nullable
    @NotNull
    @Valid
    private FilterFeature filter;
    @Nullable
    @NotNull
    @Valid
    private SupportedFeature changePassword;
    @Nullable
    @NotNull
    @Valid
    private SupportedFeature sort;
    @Nullable
    @NotNull
    @Valid
    private SupportedFeature etag;
    @Nullable
    @NotEmpty
    private List<@Valid AuthenticationScheme> authenticationSchemes;

    /**
     * Creates a configuration resource with its RFC 7643 schema URI.
     *
     * @since 5.4.0
     */
    public ServiceProviderConfig() {
        super(SchemaUris.SERVICE_PROVIDER_CONFIG);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The service provider's human-consumable documentation URI
     * @since 5.4.0
     */
    @Nullable
    public String getDocumentationUri() {
        return documentationUri;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param documentationUri The service provider's human-consumable documentation URI
     * @since 5.4.0
     */
    public void setDocumentationUri(@Nullable String documentationUri) {
        this.documentationUri = documentationUri;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return PATCH support
     * @since 5.4.0
     */
    @Nullable
    public SupportedFeature getPatch() {
        return patch;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param patch PATCH support
     * @since 5.4.0
     */
    public void setPatch(@Nullable SupportedFeature patch) {
        this.patch = patch;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Bulk operation support and limits
     * @since 5.4.0
     */
    @Nullable
    public BulkFeature getBulk() {
        return bulk;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param bulk Bulk operation support and limits
     * @since 5.4.0
     */
    public void setBulk(@Nullable BulkFeature bulk) {
        this.bulk = bulk;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Filtering support and limits
     * @since 5.4.0
     */
    @Nullable
    public FilterFeature getFilter() {
        return filter;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param filter Filtering support and limits
     * @since 5.4.0
     */
    public void setFilter(@Nullable FilterFeature filter) {
        this.filter = filter;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Password-change support
     * @since 5.4.0
     */
    @Nullable
    public SupportedFeature getChangePassword() {
        return changePassword;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param changePassword Password-change support
     * @since 5.4.0
     */
    public void setChangePassword(@Nullable SupportedFeature changePassword) {
        this.changePassword = changePassword;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Sorting support
     * @since 5.4.0
     */
    @Nullable
    public SupportedFeature getSort() {
        return sort;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param sort Sorting support
     * @since 5.4.0
     */
    public void setSort(@Nullable SupportedFeature sort) {
        this.sort = sort;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Entity-tag support
     * @since 5.4.0
     */
    @Nullable
    public SupportedFeature getEtag() {
        return etag;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param etag Entity-tag support
     * @since 5.4.0
     */
    public void setEtag(@Nullable SupportedFeature etag) {
        this.etag = etag;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return Advertised authentication schemes
     * @since 5.4.0
     */
    @Nullable
    public List<AuthenticationScheme> getAuthenticationSchemes() {
        return authenticationSchemes;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param authenticationSchemes Advertised authentication schemes
     * @since 5.4.0
     */
    public void setAuthenticationSchemes(@Nullable List<AuthenticationScheme> authenticationSchemes) {
        this.authenticationSchemes = authenticationSchemes;
    }
}
