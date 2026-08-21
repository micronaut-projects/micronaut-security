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
import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_BROWSER_INITIATED_REQUESTS,
    value = StringUtils.FALSE)
@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_SAME_ORIGIN,
    value = StringUtils.FALSE)
@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_SAME_SITE,
    value = StringUtils.TRUE)
@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_NO_FETCH_METADATA,
    value = StringUtils.FALSE)
@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_CROSS_ORIGIN,
    value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class FetchMetadataRulesConfigurationPropertiesTest {

    @Inject
    BeanContext beanContext;

    @Test
    void bindsRuleConfiguration(FetchMetadataRulesConfiguration configuration) {
        assertFalse(configuration.isAllowBrowserInitiatedRequests());
        assertFalse(configuration.isAllowSameOrigin());
        assertTrue(configuration.isAllowSameSite());
        assertFalse(configuration.isAllowNoFetchMetadata());
        assertFalse(configuration.isAllowCrossOrigin());
        assertFalse(beanContext.containsBean(CrossOriginFetchMetadataRule.class));
    }

    @Test
    void usesDocumentedDefaults() {
        FetchMetadataRulesConfigurationProperties configuration =
            new FetchMetadataRulesConfigurationProperties();

        assertTrue(configuration.isAllowBrowserInitiatedRequests());
        assertTrue(configuration.isAllowSameOrigin());
        assertFalse(configuration.isAllowSameSite());
        assertTrue(configuration.isAllowNoFetchMetadata());
        assertTrue(configuration.isAllowCrossOrigin());
    }
}
