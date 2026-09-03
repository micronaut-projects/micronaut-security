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
package io.micronaut.security.csp.conf;

import io.micronaut.core.annotation.Internal;

import java.util.Collections;
import java.util.Set;

/**
 * Base properties for source-list directives supporting {@code 'none'} and {@code 'self'}.
 */
@Internal
public abstract class SourceListDirectiveConfigurationProperties implements SourceListDirectiveConfiguration {
    private boolean enabled = true;
    private boolean none = true;
    private boolean self;
    private boolean http;
    private boolean https;
    private boolean data;
    private boolean blob;
    private boolean filesystem;
    private boolean mediastream;
    private boolean ws;
    private boolean wss;
    private Set<String> values = Collections.emptySet();

    /** Creates a source-list configuration with secure defaults. */
    public SourceListDirectiveConfigurationProperties() {
    }

    @Override
    public Set<String> getValues() {
        return values;
    }

    /**
     * Sets additional source expressions in their serialized CSP form.
     *
     * @param values additional source expressions to include in the directive
     */
    public void setValues(Set<String> values) {
        this.values = values;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables or disables generation of this directive.
     *
     * @param enabled whether the directive is emitted in the generated policy
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean isNone() {
        return none;
    }

    /**
     * Controls the {@code http:} scheme source expression.
     *
     * Sets whether the source list contains {@code 'none'}.
     *
     * @param none whether no sources are allowed
     */
    public void setNone(boolean none) {
        this.none = none;
    }

    @Override
    public boolean isSelf() {
        return self;
    }

    /**
     * Controls the {@code https:} scheme source expression.
     *
     * Sets whether the source list contains {@code 'self'}.
     *
     * @param self whether the protected origin is allowed
     */
    public void setSelf(boolean self) {
        this.self = self;
    }

    @Override
    public boolean isHttp() {
        return http;
    }

    /**
     * Controls the {@code data:} scheme source expression.
     *
     * @param http whether the directive includes the unquoted {@code http:} scheme source
     */
    public void setHttp(boolean http) {
        this.http = http;
    }

    @Override
    public boolean isHttps() {
        return https;
    }

    /**
     * Controls the {@code blob:} scheme source expression.
     *
     * @param https whether the directive includes the unquoted {@code https:} scheme source
     */
    public void setHttps(boolean https) {
        this.https = https;
    }

    @Override
    public boolean isData() {
        return data;
    }

    /**
     * Controls the {@code filesystem:} scheme source expression.
     *
     * @param data whether the directive includes the unquoted {@code data:} scheme source
     */
    public void setData(boolean data) {
        this.data = data;
    }

    @Override
    public boolean isBlob() {
        return blob;
    }

    /**
     * Controls the {@code mediastream:} scheme source expression.
     *
     * @param blob whether the directive includes the unquoted {@code blob:} scheme source
     */
    public void setBlob(boolean blob) {
        this.blob = blob;
    }

    @Override
    public boolean isFilesystem() {
        return filesystem;
    }

    /**
     * Controls the {@code ws:} scheme source expression.
     *
     * @param filesystem whether the directive includes the unquoted {@code filesystem:} scheme source
     */
    public void setFilesystem(boolean filesystem) {
        this.filesystem = filesystem;
    }

    @Override
    public boolean isMediastream() {
        return mediastream;
    }

    /**
     * Controls the {@code wss:} scheme source expression.
     *
     * @param mediastream whether the directive includes the unquoted {@code mediastream:} scheme source
     */
    public void setMediastream(boolean mediastream) {
        this.mediastream = mediastream;
    }

    @Override
    public boolean isWs() {
        return ws;
    }

    /**
     * Controls the {@code ws:} scheme source expression.
     *
     * @param ws whether the directive includes the unquoted {@code ws:} scheme source
     */
    public void setWs(boolean ws) {
        this.ws = ws;
    }

    @Override
    public boolean isWss() {
        return wss;
    }

    /**
     * Controls the {@code wss:} scheme source expression.
     *
     * @param wss whether the directive includes the unquoted {@code wss:} scheme source
     */
    public void setWss(boolean wss) {
        this.wss = wss;
    }
}
