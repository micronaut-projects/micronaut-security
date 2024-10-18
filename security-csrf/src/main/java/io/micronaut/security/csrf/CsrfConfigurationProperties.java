/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.config.SecurityConfigurationProperties;

@Internal
@ConfigurationProperties(CsrfConfigurationProperties.PREFIX)
class CsrfConfigurationProperties implements CsrfConfiguration {
    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".csrf";

    /**
     * The default HTTP Header name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_HTTP_HEADER_NAME = "X-CSRF-TOKEN";

    /**
     * The default fieldName.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_FIELD_NAME = "csrfToken";

    /**
     * The default HTTP Session name.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_HTTP_SESSION_NAME = "csrfToken";

    public static final int DEFAULT_TOKEN_SIZE = 16;

    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;

    private String headerName = DEFAULT_HTTP_HEADER_NAME;

    private String fieldName = DEFAULT_FIELD_NAME;

    private int tokenSize = DEFAULT_TOKEN_SIZE;

    private String httpSessionName = DEFAULT_HTTP_SESSION_NAME;

    @Override
    public String getHttpSessionName() {
        return httpSessionName;
    }

    /**
     * Key to look for the CSRF token in an HTTP Session. Default Value: {@value #DEFAULT_HTTP_SESSION_NAME}.
     * @param httpSessionName Key to look for the CSRF token in an HTTP Session.
     */
    public void setHttpSessionName(String httpSessionName) {
        this.httpSessionName = httpSessionName;
    }

    @Override
    public int getTokenSize() {
        return tokenSize;
    }

    /**
     * Random CSRF Token size in bytes. Default Value: {@value #DEFAULT_TOKEN_SIZE}.
     * @param tokenSize Random CSRF Token size in bytes.
     */
    public void setTokenSize(int tokenSize) {
        this.tokenSize = tokenSize;
    }

    @Override
    @NonNull
    public String getHeaderName() {
        return headerName;
    }

    /**
     * HTTP Header name to look for the CSRF token. Default Value: {@value #DEFAULT_HTTP_HEADER_NAME}.
     * @param headerName HTTP Header name to look for the CSRF token.
     */
    public void setHeaderName(@NonNull String headerName) {
        this.headerName = headerName;
    }

    @Override
    public String getFieldName() {
        return fieldName;
    }

    /**
     * Field name in a form url encoded submission  to look for the CSRF token. Default Value: {@value #DEFAULT_FIELD_NAME}.
     * @param fieldName Field name in a form url encoded submission  to look for the CSRF token.
     */
    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether the CSRF integration is enabled. Default value {@value #DEFAULT_ENABLED}.
     * @param enabled Whether the CSRF integration is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
