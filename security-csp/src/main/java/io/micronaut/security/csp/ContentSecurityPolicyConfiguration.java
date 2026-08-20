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
package io.micronaut.security.csp;

import io.micronaut.core.util.Toggleable;

import java.util.List;

/**
 * Configuration for Content Security Policy response headers.
 *
 * @since 5.4.0
 */
public interface ContentSecurityPolicyConfiguration extends Toggleable {
    /**
     * @return whether the policy is reported without being enforced
     */
    boolean isReportOnly();

    /**
     * @return whether the {@code base-uri} directive is included in the policy
     */
    boolean isBaseUriEnabled();

    /**
     * @return the source expression used as the value of the {@code base-uri} directive
     */
    List<String> getBaseUri();

    /**
     * @return whether the {@code connect-src} directive is included in the policy
     */
    boolean isConnectSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code connect-src} directive
     */
    List<String> getConnectSrc();

    /**
     * @return whether the {@code font-src} directive is included in the policy
     */
    boolean isFontSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code font-src} directive
     */
    List<String> getFontSrc();

    /**
     * @return whether the {@code object-src} directive is included in the policy
     */
    boolean isObjectSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code object-src} directive
     */
    List<String> getObjectSrc();

    /**
     * @return whether the {@code prefetch-src} directive is included in the policy
     */
    boolean isPrefetchSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code prefetch-src} directive
     */
    List<String> getPrefetchSrc();

    /**
     * @return whether the {@code require-trusted-types-for} directive is included in the policy
     */
    boolean isRequireTrustedTypesForEnabled();

    /**
     * @return the sink group required to use Trusted Types by the {@code require-trusted-types-for} directive
     */
    String getRequireTrustedTypesFor();

    /**
     * @return whether the {@code frame-ancestors} directive is included in the policy
     */
    boolean isFrameAncestorsEnabled();

    /**
     * @return the source expression used as the value of the {@code frame-ancestors} directive
     */
    List<String> getFrameAncestors();

    /**
     * @return whether the {@code frame-src} directive is included in the policy
     */
    boolean isFrameSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code frame-src} directive
     */
    List<String> getFrameSrc();

    /**
     * @return whether the {@code img-src} directive is included in the policy
     */
    boolean isImgSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code img-src} directive
     */
    List<String> getImgSrc();

    /**
     * @return whether the {@code manifest-src} directive is included in the policy
     */
    boolean isManifestSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code manifest-src} directive
     */
    List<String> getManifestSrc();

    /**
     * @return whether the {@code media-src} directive is included in the policy
     */
    boolean isMediaSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code media-src} directive
     */
    List<String> getMediaSrc();

    /**
     * @return whether the {@code form-action} directive is included in the policy
     */
    boolean isFormActionEnabled();

    /**
     * @return the source expression used as the value of the {@code form-action} directive
     */
    List<String> getFormAction();

    /**
     * @return whether a per-response nonce is added to the {@code script-src} directive
     */
    boolean isScriptSrcNonceEnabled();

    /**
     * @return whether {@code 'strict-dynamic'} is added to the {@code script-src} directive.
     * When enabled, a script trusted via the nonce may load further scripts regardless of any
     * source expression, which lets libraries that re-insert {@code <script>} elements at
     * runtime (e.g. Turbo Drive) keep working under a nonce-based policy.
     * @see <a href="https://content-security-policy.com/strict-dynamic/">strict-dynamic</a>
     */
    boolean isScriptSrcStrictDynamic();

    /**
     * @return whether the {@code style-src} directive is included in the policy
     */
    boolean isStyleSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code style-src} directive
     */
    List<String> getStyleSrc();

    /**
     * @return whether the {@code worker-src} directive is included in the policy
     */
    boolean isWorkerSrcEnabled();

    /**
     * @return the source expression used as the value of the {@code worker-src} directive
     */
    List<String> getWorkerSrc();
}
