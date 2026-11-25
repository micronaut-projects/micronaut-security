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
package io.micronaut.security.csp.conf.scriptsrc;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.InlineSourceListDirectiveConfigurationProperties;


/**
 * Mutable properties for {@link ScriptSrcConfiguration}.
 *
 * <p>Nonce source expressions are disabled by default, leaving the inherited {@code 'none'} source
 * expression as the secure default.</p>
 *
 * @since 5.6.0
 */
@Internal
@ConfigurationProperties(ContentSecurityPolicyConfigurationProperties.PROPERTY_SCRIPT_SRC)
public class ScriptSrcConfigurationProperties extends InlineSourceListDirectiveConfigurationProperties implements ScriptSrcConfiguration {
    private boolean nonce;
    private boolean unsafeEval;
    private boolean strictDynamic;
    private boolean wasmUnsafeEval;
    private boolean trustedTypesEval;
    private boolean reportSha256;
    private boolean reportSha384;
    private boolean reportSha512;

    @Override
    public boolean isNonce() {
        return nonce;
    }

    /**
     * Whether to add the nonce generated for each request, which views can apply to trusted inline
     * scripts. Default: false.
     *
     * @param nonce whether a nonce source expression is generated for this directive; defaults to {@code false}
     */
    public void setNonce(boolean nonce) {
        this.nonce = nonce;
    }

    @Override
    public boolean isUnsafeEval() {
        return unsafeEval;
    }

    /**
     * Whether to allow string-to-code APIs such as eval, with 'unsafe-eval'. This weakens the protection
     * against cross-site scripting. Default: false.
     *
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
     * Whether scripts authorized by a nonce or hash may load further scripts, with 'strict-dynamic'. CSP3
     * browsers then ignore 'self', host and scheme sources, so every script element must carry the nonce or
     * match a hash. Default: false.
     *
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
     * Whether to allow WebAssembly compilation, with 'wasm-unsafe-eval'. Default: false.
     *
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
     * Whether eval may run Trusted Types values, with 'trusted-types-eval'. Default: false.
     *
     * @param trustedTypesEval whether Trusted Types values may be evaluated as JavaScript
     */
    public void setTrustedTypesEval(boolean trustedTypesEval) {
        this.trustedTypesEval = trustedTypesEval;
    }

    @Override
    public boolean isReportSha256() {
        return reportSha256;
    }

    /**
     * Whether browsers send csp-hash reports with SHA-256 digests of loaded scripts, with 'report-sha256'.
     * Default: false.
     *
     * @param reportSha256 whether user agents send {@code csp-hash} reports with SHA-256 digests of loaded scripts
     */
    public void setReportSha256(boolean reportSha256) {
        this.reportSha256 = reportSha256;
    }

    @Override
    public boolean isReportSha384() {
        return reportSha384;
    }

    /**
     * Whether browsers send csp-hash reports with SHA-384 digests of loaded scripts, with 'report-sha384'.
     * Default: false.
     *
     * @param reportSha384 whether user agents send {@code csp-hash} reports with SHA-384 digests of loaded scripts
     */
    public void setReportSha384(boolean reportSha384) {
        this.reportSha384 = reportSha384;
    }

    @Override
    public boolean isReportSha512() {
        return reportSha512;
    }

    /**
     * Whether browsers send csp-hash reports with SHA-512 digests of loaded scripts, with 'report-sha512'.
     * Default: false.
     *
     * @param reportSha512 whether user agents send {@code csp-hash} reports with SHA-512 digests of loaded scripts
     */
    public void setReportSha512(boolean reportSha512) {
        this.reportSha512 = reportSha512;
    }
}
