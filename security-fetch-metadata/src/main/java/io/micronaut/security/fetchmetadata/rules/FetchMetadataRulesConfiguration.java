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

/**
 * Configuration for the built-in Fetch Metadata rules.
 *
 * @since 5.6.0
 */
public interface FetchMetadataRulesConfiguration {
    /** Configuration prefix for the built-in Fetch Metadata rules. */
    String PREFIX = "micronaut.security.fetch-metadata.rules";
    /** Property that controls whether browser-initiated requests are allowed. */
    String PROPERTY_ALLOW_BROWSER_INITIATED_REQUESTS = PREFIX + ".allow-browser-initiated-requests";
    /** Property that controls whether same-origin requests are allowed. */
    String PROPERTY_ALLOW_SAME_ORIGIN = PREFIX + ".allow-same-origin";
    /** Property that controls whether same-site requests are allowed. */
    String PROPERTY_ALLOW_SAME_SITE = PREFIX + ".allow-same-site";
    /** Property that controls whether requests without the {@code Sec-Fetch-Site} header are allowed. */
    String PROPERTY_ALLOW_NO_FETCH_METADATA = PREFIX + ".allow-no-fetch-metadata";
    /** Property that controls whether cross-site {@code GET} navigations, including cross-site iframing, are allowed. */
    String PROPERTY_ALLOW_SIMPLE_NAVIGATION = PREFIX + ".allow-simple-navigation";
    /** Property that controls whether permitted cross-origin requests are allowed. */
    String PROPERTY_ALLOW_CROSS_ORIGIN = PREFIX + ".allow-cross-origin";
    /**
     * Property that controls whether the simple navigation rule allows navigations to routes annotated with
     * {@link io.micronaut.security.fetchmetadata.DenyCrossSiteNavigation DenyCrossSiteNavigation}.
     */
    String PROPERTY_ALLOW_CROSS_SITE_NAVIGATION_TO_ANNOTATED_ROUTES = PREFIX + ".allow-cross-site-navigation-to-annotated-routes";

    /**
     * Whether to allow cross-origin requests to routes whose {@code @CrossOrigin} configuration accepts the request origin and HTTP method.
     *
     * @return whether the rule is enabled
     */
    boolean isAllowCrossOrigin();

    /**
     * Whether to allow requests initiated directly by a user through browser UI ({@code Sec-Fetch-Site: none}).
     *
     * @return whether the rule is enabled
     */
    boolean isAllowBrowserInitiatedRequests();

    /**
     * Whether to allow requests whose Fetch Metadata identifies their initiator as the same origin.
     *
     * @return whether the rule is enabled
     */
    boolean isAllowSameOrigin();

    /**
     * Whether to allow requests whose Fetch Metadata identifies their initiator as the same site.
     *
     * @return whether the rule is enabled
     */
    boolean isAllowSameSite();

    /**
     * Whether to allow requests without the {@code Sec-Fetch-Site} header.
     *
     * @return whether the rule is enabled
     */
    boolean isAllowNoFetchMetadata();

    /**
     * Whether to allow cross-site {@code GET} navigations, including loading the application in a cross-site {@code <iframe>}. This rule does not protect against framing; use CSP {@code frame-ancestors} for that.
     *
     * @return whether the rule is enabled
     */
    boolean isAllowSimpleNavigation();

    /**
     * Whether the simple navigation rule allows {@code GET} navigations to routes annotated with
     * {@link io.micronaut.security.fetchmetadata.DenyCrossSiteNavigation DenyCrossSiteNavigation}, such as the
     * OAuth 2.0 login route, like to any other route. When disabled, another site cannot send the browser to them.
     *
     * @return whether the simple navigation rule allows navigations to annotated routes
     */
    boolean isAllowCrossSiteNavigationToAnnotatedRoutes();
}
