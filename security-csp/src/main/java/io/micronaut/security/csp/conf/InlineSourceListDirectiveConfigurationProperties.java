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

    /** Creates an inline-capable source-list configuration with secure defaults. */
    public InlineSourceListDirectiveConfigurationProperties() {
    }

    @Override
    public boolean isUnsafeInline() {
        return unsafeInline;
    }

    /**
     * Controls the {@code 'unsafe-inline'} keyword source expression.
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
     * Controls the {@code 'unsafe-hashes'} keyword source expression.
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
     * Controls the {@code 'report-sample'} keyword source expression.
     *
     * @param reportSample whether violation reports include a sample of blocked inline content
     */
    public void setReportSample(boolean reportSample) {
        this.reportSample = reportSample;
    }
}
