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
package io.micronaut.security.fetchmetadata.rules;

import io.micronaut.context.annotation.ConfigurationProperties;

/**
 * Binds configuration for the built-in Fetch Metadata rules.
 *
 * @since 5.6.0
 */
@ConfigurationProperties(FetchMetadataRulesConfigurationProperties.PREFIX)
final class FetchMetadataRulesConfigurationProperties implements FetchMetadataRulesConfiguration {
    /** Default browser-initiated request behavior. */
    public static final boolean DEFAULT_ALLOW_BROWSER_INITIATED_REQUESTS = true;
    /** Default same-site request behavior. */
    public static final boolean DEFAULT_ALLOW_SAME_SITE = false;
    /** Default same-origin request behavior. */
    public static final boolean DEFAULT_ALLOW_SAME_ORIGIN = true;
    /** Default behavior for requests without the {@code Sec-Fetch-Site} header. */
    public static final boolean DEFAULT_ALLOW_NO_FETCH_METADATA = true;
    /** Default simple cross-site navigation and iframing behavior. */
    public static final boolean DEFAULT_ALLOW_SIMPLE_NAVIGATION = true;
    /** Default permitted cross-origin request behavior. */
    public static final boolean DEFAULT_ALLOW_CROSS_ORIGIN = true;

    private boolean allowNoFetchMetadata = DEFAULT_ALLOW_NO_FETCH_METADATA;
    private boolean allowBrowserInitiatedRequests = DEFAULT_ALLOW_BROWSER_INITIATED_REQUESTS;
    private boolean allowSameOrigin = DEFAULT_ALLOW_SAME_ORIGIN;
    private boolean allowSameSite = DEFAULT_ALLOW_SAME_SITE;
    private boolean allowSimpleNavigation = DEFAULT_ALLOW_SIMPLE_NAVIGATION;
    private boolean allowCrossOrigin = DEFAULT_ALLOW_CROSS_ORIGIN;

    @Override
    public boolean isAllowCrossOrigin() {
        return allowCrossOrigin;
    }

    /**
     * Whether to allow cross-origin requests to routes whose {@code @CrossOrigin} configuration accepts the request origin and HTTP method. Default value: {@value #DEFAULT_ALLOW_CROSS_ORIGIN}.
     * @param allowCrossOrigin whether permitted cross-origin requests are allowed
     */
    public void setAllowCrossOrigin(boolean allowCrossOrigin) {
        this.allowCrossOrigin = allowCrossOrigin;
    }

    @Override
    public boolean isAllowBrowserInitiatedRequests() {
        return allowBrowserInitiatedRequests;
    }

    /**
     * Whether to allow requests initiated directly by a user through browser UI ({@code Sec-Fetch-Site: none}). Default value: {@value #DEFAULT_ALLOW_BROWSER_INITIATED_REQUESTS}
     *
     * @param allowBrowserInitiatedRequests whether requests initiated through browser UI are allowed
     */
    public void setAllowBrowserInitiatedRequests(boolean allowBrowserInitiatedRequests) {
        this.allowBrowserInitiatedRequests = allowBrowserInitiatedRequests;
    }

    @Override
    public boolean isAllowSameOrigin() {
        return allowSameOrigin;
    }

    /**
     * Whether to allow requests whose Fetch Metadata identifies their initiator as the same origin. Default value: {@value #DEFAULT_ALLOW_SAME_ORIGIN}
     *
     * @param allowSameOrigin whether same-origin requests are allowed
     */
    public void setAllowSameOrigin(boolean allowSameOrigin) {
        this.allowSameOrigin = allowSameOrigin;
    }

    @Override
    public boolean isAllowSameSite() {
        return allowSameSite;
    }

    /**
     * Whether to allow requests whose Fetch Metadata identifies their initiator as the same site. Default value: {@value #DEFAULT_ALLOW_SAME_SITE}
     *
     * @param allowSameSite whether same-site requests are allowed
     */
    public void setAllowSameSite(boolean allowSameSite) {
        this.allowSameSite = allowSameSite;
    }

    @Override
    public boolean isAllowNoFetchMetadata() {
        return allowNoFetchMetadata;
    }

    /**
     * Whether to allow requests without the {@code Sec-Fetch-Site} header. Default value: {@value #DEFAULT_ALLOW_NO_FETCH_METADATA}
     *
     * @param allowNoFetchMetadata whether requests without the {@code Sec-Fetch-Site} header are allowed
     */
    public void setAllowNoFetchMetadata(boolean allowNoFetchMetadata) {
        this.allowNoFetchMetadata = allowNoFetchMetadata;
    }

    @Override
    public boolean isAllowSimpleNavigation() {
        return allowSimpleNavigation;
    }

    /**
     * Whether to allow cross-site {@code GET} navigations, including loading the application in a cross-site {@code <iframe>}. This rule does not protect against framing; use CSP {@code frame-ancestors} for that. Default value: {@value #DEFAULT_ALLOW_SIMPLE_NAVIGATION}
     *
     * @param allowSimpleNavigation whether simple cross-site navigations and iframing are allowed
     */
    public void setAllowSimpleNavigation(boolean allowSimpleNavigation) {
        this.allowSimpleNavigation = allowSimpleNavigation;
    }
}
