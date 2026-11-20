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

import io.micronaut.context.BeanContext;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Each built-in rule repeats its default in {@code @Requires(defaultValue = ...)}, so this test
 * keeps those defaults in sync with the documented defaults of the configuration properties.
 */
@MicronautTest(startApplication = false)
class BuiltInFetchMetadataRuleDefaultsTest {

    @Inject
    BeanContext beanContext;

    @Test
    void ruleBeansWithoutConfigurationMatchTheDocumentedDefaults() {
        assertEquals(FetchMetadataRulesConfigurationProperties.DEFAULT_ALLOW_NO_FETCH_METADATA,
            beanContext.containsBean(NoFetchMetadataRule.class), "no fetch metadata rule");
        assertEquals(FetchMetadataRulesConfigurationProperties.DEFAULT_ALLOW_SAME_ORIGIN,
            beanContext.containsBean(SameOriginFetchMetadataRule.class), "same-origin rule");
        assertEquals(FetchMetadataRulesConfigurationProperties.DEFAULT_ALLOW_SAME_SITE,
            beanContext.containsBean(SameSiteFetchMetadataRule.class), "same-site rule");
        assertEquals(FetchMetadataRulesConfigurationProperties.DEFAULT_ALLOW_BROWSER_INITIATED_REQUESTS,
            beanContext.containsBean(BrowserInitiatedRequestFetchMetadataRule.class), "browser-initiated rule");
        assertEquals(FetchMetadataRulesConfigurationProperties.DEFAULT_ALLOW_SIMPLE_NAVIGATION,
            beanContext.containsBean(SimpleTopLevelNavigationAndIframingFetchMetadataRule.class), "simple navigation rule");
        assertEquals(FetchMetadataRulesConfigurationProperties.DEFAULT_ALLOW_CROSS_ORIGIN,
            beanContext.containsBean(CrossOriginFetchMetadataRule.class), "cross-origin rule");
    }
}
