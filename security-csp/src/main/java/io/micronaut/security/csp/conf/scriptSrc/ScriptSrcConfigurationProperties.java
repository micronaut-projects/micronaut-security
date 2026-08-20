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
package io.micronaut.security.csp.conf.scriptSrc;

import io.micronaut.security.csp.conf.InlineSourceListDirectiveConfigurationProperties;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;

import io.micronaut.context.annotation.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

/** Mutable properties for {@link ScriptSrcConfiguration}. @since 5.4.0 */
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PREFIX + ".script-src")
public class ScriptSrcConfigurationProperties extends InlineSourceListDirectiveConfigurationProperties implements ScriptSrcConfiguration {
    private boolean nonce = true;
    private List<String> hashes = Collections.emptyList();
    private List<String> urls = Collections.emptyList();
    private boolean unsafeEval;
    private boolean strictDynamic;
    private boolean wasmUnsafeEval;
    private boolean trustedTypesEval;

    @Override
    public boolean isNonce() {
        return nonce;
    }

    /**
     * @param nonce whether a nonce source expression is generated for this directive
     */
    public void setNonce(boolean nonce) {
        this.nonce = nonce;
    }

    @Override
    public List<String> getHashes() {
        return hashes;
    }

    /**
     * @param hashes hash source expressions to add to the directive
     */
    public void setHashes(List<String> hashes) {
        this.hashes = hashes;
    }

    @Override
    public List<String> getUrls() {
        return urls;
    }

    /**
     * @param urls URL source expressions to add to the directive
     */
    public void setUrls(List<String> urls) {
        this.urls = urls;
    }

    @Override
    public boolean isUnsafeEval() {
        return unsafeEval;
    }

    /**
     * @param unsafeEval whether JavaScript string-to-code APIs are allowed
     */
    public void setUnsafeEval(boolean unsafeEval) {
        this.unsafeEval = unsafeEval;
    }

    @Override
    public boolean isStrictDynamic() {
        return strictDynamic;
    }

    /**
     * @param strictDynamic whether trusted scripts may load further scripts dynamically
     */
    public void setStrictDynamic(boolean strictDynamic) {
        this.strictDynamic = strictDynamic;
    }

    @Override
    public boolean isWasmUnsafeEval() {
        return wasmUnsafeEval;
    }

    /**
     * @param wasmUnsafeEval whether WebAssembly compilation is allowed
     */
    public void setWasmUnsafeEval(boolean wasmUnsafeEval) {
        this.wasmUnsafeEval = wasmUnsafeEval;
    }

    @Override
    public boolean isTrustedTypesEval() {
        return trustedTypesEval;
    }

    /**
     * @param trustedTypesEval whether Trusted Types values may be evaluated as JavaScript
     */
    public void setTrustedTypesEval(boolean trustedTypesEval) {
        this.trustedTypesEval = trustedTypesEval;
    }
}
