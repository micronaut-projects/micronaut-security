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
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * RFC 7643 Group resource.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public final class Group extends ScimResource {
    @Nullable
    @NotBlank
    private String displayName;
    @Nullable
    private List<@Valid ResourceReference> members;

    /**
     * Creates a Group with the RFC 7643 Group schema URI.
     *
     * @since 5.4.0
     */
    public Group() {
        super(SchemaUris.GROUP);
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The human-readable Group name
     * @since 5.4.0
     */
    @Nullable
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param displayName The human-readable Group name
     * @since 5.4.0
     */
    public void setDisplayName(@Nullable String displayName) {
        this.displayName = displayName;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The Group's User and Group members
     * @since 5.4.0
     */
    @Nullable
    public List<ResourceReference> getMembers() {
        return members;
    }

    /**
     * Updates the described SCIM value.
     *
     * @param members The Group's User and Group members
     * @since 5.4.0
     */
    public void setMembers(@Nullable List<ResourceReference> members) {
        this.members = members;
    }
}
