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
import io.micronaut.security.csp.conf.baseuri.BaseUriConfigurationProperties;
import io.micronaut.security.csp.conf.defaultsrc.DefaultSrcConfigurationProperties;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fencedframesrc.FencedFrameSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fontsrc.FontSrcConfigurationProperties;
import io.micronaut.security.csp.conf.objectsrc.ObjectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.prefetchsrc.PrefetchSrcConfigurationProperties;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfigurationProperties;
import io.micronaut.security.csp.conf.frameancestors.FrameAncestorsConfigurationProperties;
import io.micronaut.security.csp.conf.framesrc.FrameSrcConfigurationProperties;
import io.micronaut.security.csp.conf.manifestsrc.ManifestSrcConfigurationProperties;
import io.micronaut.security.csp.conf.mediasrc.MediaSrcConfigurationProperties;
import io.micronaut.security.csp.conf.formaction.FormActionConfigurationProperties;
import io.micronaut.security.csp.conf.stylesrc.StyleSrcConfigurationProperties;
import io.micronaut.security.csp.conf.workersrc.WorkerSrcConfigurationProperties;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfiguration;
import io.micronaut.security.csp.conf.reporturi.ReportUriConfiguration;
import io.micronaut.security.csp.conf.reporturi.ReportUriConfigurationProperties;
import io.micronaut.security.csp.conf.requiretrustedtypesfor.RequireTrustedTypesForConfiguration;
import io.micronaut.security.csp.conf.requiretrustedtypesfor.RequireTrustedTypesForConfigurationProperties;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfigurationProperties;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfiguration;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
            assertSame(context.getBean(ReportUriConfiguration.class), configurations.getReportUri());
            assertSame(context.getBean(RequireTrustedTypesForConfiguration.class), configurations.getRequireTrustedTypesFor());
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
        assertFalse(configurations.getReportUri().isEnabled());
        assertTrue(configurations.getReportUri().getValues().isEmpty());
        assertTrue(configurations.getRequireTrustedTypesFor().isEnabled());
        assertEquals("'script'", configurations.getRequireTrustedTypesFor().getValue());
    }

    @Test
    void builderSetsEveryDirective() {
        BaseUriConfigurationProperties baseUri = new BaseUriConfigurationProperties();
        DefaultSrcConfigurationProperties defaultSrc = new DefaultSrcConfigurationProperties();
        ConnectSrcConfigurationProperties connectSrc = new ConnectSrcConfigurationProperties();
        FencedFrameSrcConfigurationProperties fencedFrameSrc = new FencedFrameSrcConfigurationProperties();
        FontSrcConfigurationProperties fontSrc = new FontSrcConfigurationProperties();
        ObjectSrcConfigurationProperties objectSrc = new ObjectSrcConfigurationProperties();
        PrefetchSrcConfigurationProperties prefetchSrc = new PrefetchSrcConfigurationProperties();
        ReportToConfigurationProperties reportTo = new ReportToConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        FrameAncestorsConfigurationProperties frameAncestors = new FrameAncestorsConfigurationProperties();
        FrameSrcConfigurationProperties frameSrc = new FrameSrcConfigurationProperties();
        ImgSrcConfigurationProperties imgSrc = new ImgSrcConfigurationProperties();
        ManifestSrcConfigurationProperties manifestSrc = new ManifestSrcConfigurationProperties();
        MediaSrcConfigurationProperties mediaSrc = new MediaSrcConfigurationProperties();
        FormActionConfigurationProperties formAction = new FormActionConfigurationProperties();
        StyleSrcConfigurationProperties styleSrc = new StyleSrcConfigurationProperties();
        WorkerSrcConfigurationProperties workerSrc = new WorkerSrcConfigurationProperties();
        ReportUriConfigurationProperties reportUri = new ReportUriConfigurationProperties();
        RequireTrustedTypesForConfigurationProperties requireTrustedTypesFor = new RequireTrustedTypesForConfigurationProperties();

        ContentSecurityPolicyDirectiveConfigurations configurations = ContentSecurityPolicyDirectiveConfigurations.builder()
            .baseUri(baseUri)
            .defaultSrc(defaultSrc)
            .connectSrc(connectSrc)
            .fencedFrameSrc(fencedFrameSrc)
            .fontSrc(fontSrc)
            .objectSrc(objectSrc)
            .prefetchSrc(prefetchSrc)
            .reportTo(reportTo)
            .scriptSrc(scriptSrc)
            .frameAncestors(frameAncestors)
            .frameSrc(frameSrc)
            .imgSrc(imgSrc)
            .manifestSrc(manifestSrc)
            .mediaSrc(mediaSrc)
            .formAction(formAction)
            .styleSrc(styleSrc)
            .workerSrc(workerSrc)
            .reportUri(reportUri)
            .requireTrustedTypesFor(requireTrustedTypesFor)
            .build();

        assertSame(baseUri, configurations.getBaseUri());
        assertSame(defaultSrc, configurations.getDefaultSrc());
        assertSame(connectSrc, configurations.getConnectSrc());
        assertSame(fencedFrameSrc, configurations.getFencedFrameSrc());
        assertSame(fontSrc, configurations.getFontSrc());
        assertSame(objectSrc, configurations.getObjectSrc());
        assertSame(prefetchSrc, configurations.getPrefetchSrc());
        assertSame(reportTo, configurations.getReportTo());
        assertSame(scriptSrc, configurations.getScriptSrc());
        assertSame(frameAncestors, configurations.getFrameAncestors());
        assertSame(frameSrc, configurations.getFrameSrc());
        assertSame(imgSrc, configurations.getImgSrc());
        assertSame(manifestSrc, configurations.getManifestSrc());
        assertSame(mediaSrc, configurations.getMediaSrc());
        assertSame(formAction, configurations.getFormAction());
        assertSame(styleSrc, configurations.getStyleSrc());
        assertSame(workerSrc, configurations.getWorkerSrc());
        assertSame(reportUri, configurations.getReportUri());
        assertSame(requireTrustedTypesFor, configurations.getRequireTrustedTypesFor());
    }
}
