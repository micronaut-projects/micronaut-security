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
 * @since 5.4.0
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
    /** Property that controls whether requests without parsed Fetch Metadata are allowed. */
    String PROPERTY_ALLOW_NO_FETCH_METADATA = PREFIX + ".allow-no-fetch-metadata";
    /** Property that controls whether permitted cross-origin requests are allowed. */
    String PROPERTY_ALLOW_CROSS_ORIGIN = PREFIX + ".allow-cross-origin";

    /**
     * @return Whether to enable {@link CrossOriginFetchMetadataRule} bean which allows a cross-origin request when its matched route declares a CORS configuration that permits the request origin and HTTP method.
     */
    boolean isAllowCrossOrigin();

    /**
     * @return Whether to enable {@link BrowserInitiatedRequestFetchMetadataRule} bean which allows requests initiated directly by a user through browser UI, represented by site: none.
     */
    boolean isAllowBrowserInitiatedRequests();

    /**
     * @return Whether to enable {@link SameOriginFetchMetadataRule} bean which allows requests whose Fetch Metadata identifies their initiator as the same origin.
     */
    boolean isAllowSameOrigin();

    /**
     * @return Whether to enable {@link SameSiteFetchMetadataRule} bean which allows requests whose Fetch Metadata identifies their initiator as the same site.
     */
    boolean isAllowSameSite();

    /**
     * @return Whether to enable {@link NoFetchMetadataRule} bean which allows requests without a complete set of Fetch Metadata headers.
     */
    boolean isAllowNoFetchMetadata();
}
