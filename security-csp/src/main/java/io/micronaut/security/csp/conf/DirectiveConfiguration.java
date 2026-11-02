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

import io.micronaut.core.util.Toggleable;

/**
 * Configures keyword and scheme source expressions supported by a CSP directive.
 *
 * <p>Every optional expression defaults to disabled. Implementations override the expressions
 * they support, normally by exposing mutable configuration properties. CSP keywords are emitted
 * with single quotes; scheme source expressions are emitted without quotes.</p>
 *
 * @since 5.4.0
 */
public interface DirectiveConfiguration extends Toggleable {
    /**
     * Controls the {@code 'none'} keyword source expression.
     *
     * @return whether the directive includes {@code 'none'}
     */
    default boolean isNone() {
        return false;
    }

    /**
     * Controls the {@code 'self'} keyword source expression.
     *
     * @return whether the directive includes {@code 'self'}
     */
    default boolean isSelf() {
        return false;
    }

    /**
     * Controls the {@code 'unsafe-inline'} keyword source expression.
     *
     * @return whether the directive includes {@code 'unsafe-inline'}
     */
    default boolean isUnsafeInline() {
        return false;
    }

    /**
     * Controls the {@code 'unsafe-eval'} keyword source expression.
     *
     * @return whether the directive includes {@code 'unsafe-eval'}
     */
    default boolean isUnsafeEval() {
        return false;
    }

    /**
     * Controls the {@code 'strict-dynamic'} keyword source expression.
     *
     * @return whether the directive includes {@code 'strict-dynamic'}
     */
    default boolean isStrictDynamic() {
        return false;
    }

    /**
     * Controls the {@code 'unsafe-hashes'} keyword source expression.
     *
     * @return whether the directive includes {@code 'unsafe-hashes'}
     */
    default boolean isUnsafeHashes() {
        return false;
    }

    /**
     * Controls the {@code 'report-sample'} keyword source expression.
     *
     * @return whether the directive includes {@code 'report-sample'}
     */
    default boolean isReportSample() {
        return false;
    }

    /**
     * Controls the {@code 'unsafe-allow-redirects'} keyword source expression.
     *
     * @return whether the directive includes {@code 'unsafe-allow-redirects'}
     */
    default boolean isUnsafeAllowRedirects() {
        return false;
    }

    /**
     * Controls the {@code 'wasm-unsafe-eval'} keyword source expression.
     *
     * @return whether the directive includes {@code 'wasm-unsafe-eval'}
     */
    default boolean isWasmUnsafeEval() {
        return false;
    }

    /**
     * Controls the {@code 'trusted-types-eval'} keyword source expression.
     *
     * @return whether the directive includes {@code 'trusted-types-eval'}
     */
    default boolean isTrustedTypesEval() {
        return false;
    }

    /**
     * Controls the {@code 'report-sha256'} keyword source expression.
     *
     * @return whether the directive includes {@code 'report-sha256'}
     */
    default boolean isReportSha256() {
        return false;
    }

    /**
     * Controls the {@code 'report-sha384'} keyword source expression.
     *
     * @return whether the directive includes {@code 'report-sha384'}
     */
    default boolean isReportSha384() {
        return false;
    }

    /**
     * Controls the {@code 'report-sha512'} keyword source expression.
     *
     * @return whether the directive includes {@code 'report-sha512'}
     */
    default boolean isReportSha512() {
        return false;
    }

    /**
     * Controls the {@code 'unsafe-webtransport-hashes'} keyword source expression.
     *
     * @return whether the directive includes {@code 'unsafe-webtransport-hashes'}
     */
    default boolean isUnsafeWebtransportHashes() {
        return false;
    }

    /**
     * Controls the {@code http:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code http:} scheme source
     * @since 5.4.0
     */
    default boolean isHttp() {
        return false;
    }

    /**
     * Controls the {@code https:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code https:} scheme source
     * @since 5.4.0
     */
    default boolean isHttps() {
        return false;
    }

    /**
     * Controls the {@code data:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code data:} scheme source
     * @since 5.4.0
     */
    default boolean isData() {
        return false;
    }

    /**
     * Controls the {@code blob:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code blob:} scheme source
     * @since 5.4.0
     */
    default boolean isBlob() {
        return false;
    }

    /**
     * Controls the {@code filesystem:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code filesystem:} scheme source
     * @since 5.4.0
     */
    default boolean isFilesystem() {
        return false;
    }

    /**
     * Controls the {@code mediastream:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code mediastream:} scheme source
     * @since 5.4.0
     */
    default boolean isMediastream() {
        return false;
    }

    /**
     * Controls the {@code ws:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code ws:} scheme source
     * @since 5.4.0
     */
    default boolean isWs() {
        return false;
    }

    /**
     * Controls the {@code wss:} scheme source expression.
     *
     * @return whether the directive includes the unquoted {@code wss:} scheme source
     * @since 5.4.0
     */
    default boolean isWss() {
        return false;
    }
}
