/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.context;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.attr.MutableAttributeHolder;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;

/**
 * Internal {@link SecurityContext} implementation backed by a {@link MutableAttributeHolder}.
 * <p>
 * It reads the authentication and token attributes written by {@link SecurityFilter}.
 *
 * @since 4.18.0
 */
@Internal
class MutableAttributeHolderSecurityContext implements SecurityContext {
    @Nullable
    private final MutableAttributeHolder attributeHolder;

    /**
     * @param attributeHolder The attribute holder containing the security attributes
     */
    MutableAttributeHolderSecurityContext(@Nullable MutableAttributeHolder attributeHolder) {
        this.attributeHolder = attributeHolder;
    }

    @Override
    @Nullable
    public Authentication getAuthentication() {
        if (attributeHolder == null) {
            return null;
        }
        return attributeHolder.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null);
    }

    @Override
    @Nullable
    public String getToken() {
        if (attributeHolder == null) {
            return null;
        }
        return attributeHolder.getAttribute(SecurityFilter.TOKEN, String.class).orElse(null);
    }

    @Override
    public void setAuthentication(@Nullable Authentication authentication) {
        if (attributeHolder != null) {
            attributeHolder.setAttribute(SecurityFilter.AUTHENTICATION, authentication);
        }
    }

    @Override
    public void setToken(@Nullable String token) {
        if (attributeHolder != null) {
            attributeHolder.setAttribute(SecurityFilter.TOKEN, token);
        }
    }

    @Override
    public void setRejectionStatus(@Nullable Integer statusCode) {
        if (attributeHolder != null) {
            attributeHolder.setAttribute(SecurityFilter.REJECTION, statusCode == null ? null : HttpStatus.valueOf(statusCode));
        }
    }

    @Override
    @Nullable
    public Integer getRejectionStatus() {
        if (attributeHolder == null) {
            return null;
        }
        return attributeHolder.getAttribute(SecurityFilter.REJECTION, HttpStatus.class)
            .map(HttpStatus::getCode)
            .orElse(null);
    }

    @Override
    public void clear() {
        if (attributeHolder != null) {
            attributeHolder.setAttribute(SecurityFilter.REJECTION, null);
        }
        setRejectionStatus(null);
        setToken(null);
        setAuthentication(null);
    }
}
