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

/**
 * Base properties for source lists that control inline script or style behavior.
 */
@Internal
public abstract class InlineSourceListDirectiveConfigurationProperties extends SourceListDirectiveConfigurationProperties {
    private boolean unsafeInline;
    private boolean unsafeHashes;
    private boolean reportSample;

    @Override
    public boolean isUnsafeInline() {
        return unsafeInline;
    }

    /**
     * Whether to allow inline content that has no nonce or hash, with 'unsafe-inline'. This weakens the
     * protection against cross-site scripting. Browsers ignore it when the directive also has a nonce or
     * hash. Default: false.
     *
     * @param unsafeInline whether to allow inline content without a nonce or hash
     */
    public void setUnsafeInline(boolean unsafeInline) {
        this.unsafeInline = unsafeInline;
    }

    @Override
    public boolean isUnsafeHashes() {
        return unsafeHashes;
    }

    /**
     * Whether hashes may also authorize event-handler and style attributes, with 'unsafe-hashes'. Default:
     * false.
     *
     * @param unsafeHashes whether hashes may authorize event handlers and style attributes
     */
    public void setUnsafeHashes(boolean unsafeHashes) {
        this.unsafeHashes = unsafeHashes;
    }

    @Override
    public boolean isReportSample() {
        return reportSample;
    }

    /**
     * Whether violation reports include a sample of the blocked content, with 'report-sample'. Default:
     * false.
     *
     * @param reportSample whether violation reports include a sample of blocked inline content
     */
    public void setReportSample(boolean reportSample) {
        this.reportSample = reportSample;
    }
}
