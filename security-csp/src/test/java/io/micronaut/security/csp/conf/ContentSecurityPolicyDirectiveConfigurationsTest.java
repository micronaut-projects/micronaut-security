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

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfiguration;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfigurationProperties;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfiguration;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentSecurityPolicyDirectiveConfigurationsTest {

    @Test
    void beanHoldsTheConfigurationBoundFromProperties() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("micronaut.security.csp.script-src.nonce", true))) {
            ContentSecurityPolicyDirectiveConfigurations configurations = context.getBean(ContentSecurityPolicyDirectiveConfigurations.class);

            assertSame(context.getBean(ImgSrcConfiguration.class), configurations.getImgSrc());
            assertSame(context.getBean(ScriptSrcConfiguration.class), configurations.getScriptSrc());
            assertTrue(configurations.getScriptSrc().isNonce());
            assertFalse(configurations.getStyleSrc().isNonce());
        }
    }

    @Test
    void builderKeepsDefaultsForDirectivesThatAreNotSet() {
        ImgSrcConfigurationProperties imgSrc = new ImgSrcConfigurationProperties();

        ContentSecurityPolicyDirectiveConfigurations configurations = ContentSecurityPolicyDirectiveConfigurations.builder()
            .imgSrc(imgSrc)
            .build();

        assertSame(imgSrc, configurations.getImgSrc());
        assertFalse(configurations.getScriptSrc().isNonce());
        assertFalse(configurations.getReportTo().isEnabled());
        assertFalse(configurations.getPrefetchSrc().isEnabled());
    }
}
