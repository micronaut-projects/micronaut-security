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
import java.util.List;

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
    private List<String> values = Collections.emptyList();

    @Override
    public List<String> getValues() {
        return values;
    }

    /**
     * Additional source expressions, written in the configured order after the keyword and scheme sources.
     * Write keywords, nonces and hashes with their single quotes, for example "'sha256-...'"; host and
     * scheme sources are written as supplied. Default: empty.
     *
     * @param values additional source expressions to include in the directive
     */
    public void setValues(List<String> values) {
        this.values = values;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Whether the directive is written to the policy. Default: true, except for prefetch-src and
     * fenced-frame-src, which default to false.
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
     * Whether to write 'none' when no other source expression is enabled. With false and no other source,
     * a fetch directive is omitted and the browser falls back to default-src. base-uri, form-action and
     * frame-ancestors have no such fallback, so they are written as 'none' whenever no other source is
     * enabled; set enabled to false to omit them. Default: true.
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
     * Whether to allow the application's own origin with 'self'. Default: false, except for form-action,
     * which defaults to true.
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
     * Whether to allow any URL with the http: scheme. Default: false.
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
     * Whether to allow any URL with the https: scheme. Default: false.
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
     * Whether to allow data: URLs. Default: false.
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
     * Whether to allow blob: URLs. Default: false.
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
     * Whether to allow filesystem: URLs. Default: false.
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
     * Whether to allow mediastream: URLs. Default: false.
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
     * Whether to allow WebSocket ws: URLs. Default: false.
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
     * Whether to allow secure WebSocket wss: URLs. Default: false.
     *
     * @param wss whether the directive includes the unquoted {@code wss:} scheme source
     */
    public void setWss(boolean wss) {
        this.wss = wss;
    }
}
