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

import io.micronaut.http.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ContentSecurityPolicyTest {

    @Test
    void parsesHeaderValue() {
        ContentSecurityPolicy policy = ContentSecurityPolicy.of(
                "default-src 'self'; ; img-src https://images.example.com; upgrade-insecure-requests");

        assertEquals(List.of(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'self'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "https://images.example.com"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS, null)
        ), policy.directives());
    }

    @Test
    void returnsNullForMissingHeader() {
        assertNull(ContentSecurityPolicy.of(HttpResponse.ok()));
    }

    @Test
    void findsStandardDirectives() {
        ContentSecurityPolicy policy = ContentSecurityPolicy.of("""
                base-uri base; child-src child; connect-src connect; default-src default; fenced-frame-src fenced; font-src font;
                form-action form; frame-ancestors ancestors; frame-src frame; img-src image; manifest-src manifest;
                media-src media; object-src object; prefetch-src prefetch; report-to report;
                report-uri https://example.com/csp-reports; require-trusted-types-for 'script'; sandbox allow-scripts; script-src script;
                script-src-attr script-attr; script-src-elem script-elem; style-src style;
                style-src-attr style-attr; style-src-elem style-elem; trusted-types trusted;
                upgrade-insecure-requests; worker-src worker
                """);

        assertEquals(new ContentSecurityPolicyDirective("base-uri", "base"), policy.baseUri());
        assertEquals(new ContentSecurityPolicyDirective("child-src", "child"), policy.childSrc());
        assertEquals(new ContentSecurityPolicyDirective("connect-src", "connect"), policy.connectSrc());
        assertEquals(new ContentSecurityPolicyDirective("default-src", "default"), policy.defaultSrc());
        assertEquals(new ContentSecurityPolicyDirective("fenced-frame-src", "fenced"), policy.fencedFrameSrc());
        assertEquals(new ContentSecurityPolicyDirective("font-src", "font"), policy.fontSrc());
        assertEquals(new ContentSecurityPolicyDirective("form-action", "form"), policy.formAction());
        assertEquals(new ContentSecurityPolicyDirective("frame-ancestors", "ancestors"), policy.frameAncestors());
        assertEquals(new ContentSecurityPolicyDirective("frame-src", "frame"), policy.frameSrc());
        assertEquals(new ContentSecurityPolicyDirective("img-src", "image"), policy.imgSrc());
        assertEquals(new ContentSecurityPolicyDirective("manifest-src", "manifest"), policy.manifestSrc());
        assertEquals(new ContentSecurityPolicyDirective("media-src", "media"), policy.mediaSrc());
        assertEquals(new ContentSecurityPolicyDirective("object-src", "object"), policy.objectSrc());
        assertEquals(new ContentSecurityPolicyDirective("prefetch-src", "prefetch"), policy.prefetchSrc());
        assertEquals(new ContentSecurityPolicyDirective("report-to", "report"), policy.reportTo());
        assertEquals(new ContentSecurityPolicyDirective("report-uri", "https://example.com/csp-reports"), policy.reportUri());
        assertEquals(new ContentSecurityPolicyDirective("require-trusted-types-for", "'script'"), policy.requireTrustedTypesFor());
        assertEquals(new ContentSecurityPolicyDirective("sandbox", "allow-scripts"), policy.sandbox());
        assertEquals(new ContentSecurityPolicyDirective("script-src", "script"), policy.scriptSrc());
        assertEquals(new ContentSecurityPolicyDirective("script-src-attr", "script-attr"), policy.scriptSrcAttr());
        assertEquals(new ContentSecurityPolicyDirective("script-src-elem", "script-elem"), policy.scriptSrcElem());
        assertEquals(new ContentSecurityPolicyDirective("style-src", "style"), policy.styleSrc());
        assertEquals(new ContentSecurityPolicyDirective("style-src-attr", "style-attr"), policy.styleSrcAttr());
        assertEquals(new ContentSecurityPolicyDirective("style-src-elem", "style-elem"), policy.styleSrcElem());
        assertEquals(new ContentSecurityPolicyDirective("trusted-types", "trusted"), policy.trustedTypes());
        assertEquals(new ContentSecurityPolicyDirective("upgrade-insecure-requests", null), policy.upgradeInsecureRequests());
        assertEquals(new ContentSecurityPolicyDirective("worker-src", "worker"), policy.workerSrc());
        assertNull(ContentSecurityPolicy.of("object-src 'none'").styleSrc());
    }

    @Test
    void realWorldParsingOfContentSecurityPolicy() {
        String chatGptSecurityPolicy = "default-src 'self'; script-src 'nonce-17d4cc4b-2675-4771-a75e-4a3de778af6b' 'self' 'sha256-Z5we4+MWtdDkWs67HhZwjrbqNxc9ymzHYfHGNEF7JoM=' 'wasm-unsafe-eval' chatgpt.com/ces https://*.chatgpt.com https://*.chatgpt.com/ https://*.js.stripe.com https://*.oaistatic.com https://accounts.google.com/gsi/client https://cdn.plaid.com/link/v2/stable/link-initialize.js https://cdn.withpersona.com https://chat.openai.com https://chatgpt.com https://chatgpt.com/ https://chatgpt.com/backend-anon https://chatgpt.com/backend-api https://chatgpt.com/backend/se https://chatgpt.com/public-api https://js.stripe.com https://oaistatic.com https://snc.apps.openai.com wss://*.chatgpt.com wss://*.chatgpt.com/; script-src-elem 'nonce-17d4cc4b-2675-4771-a75e-4a3de778af6b' 'self' 'sha256-Z5we4+MWtdDkWs67HhZwjrbqNxc9ymzHYfHGNEF7JoM=' 'sha256-eMuh8xiwcX72rRYNAGENurQBAcH7kLlAUQcoOri3BIo=' 'sha384-Sr5xwyR0H5rcDXa7/iDJDM3qBBvtHuR97A8ELbd+DFBDi32Caf72to9UVqvI8R95' auth0.openai.com blob: challenges.cloudflare.com chatgpt.com/ces https://*.chatgpt.com https://*.chatgpt.com/ https://*.js.stripe.com https://*.oaistatic.com https://analytics.tiktok.com https://apis.google.com https://bat.bing.com https://cdn.openaimerge.com/initialize.js https://cdn.plaid.com/link/v2/stable/link-initialize.js https://cdn.platform.openai.com https://cdn.withpersona.com https://chat.openai.com https://chatgpt.com https://chatgpt.com/ https://chatgpt.com/backend-anon https://chatgpt.com/backend-api https://chatgpt.com/backend/se https://chatgpt.com/public-api https://connect.facebook.net https://docs.google.com https://js.live.net/v7.2/OneDrive.js https://js.stripe.com https://oaistatic.com https://pixel-config.reddit.com https://snap.licdn.com https://snc.apps.openai.com https://www-onepick-opensocial.googleusercontent.com https://www.redditstatic.com https://www.youtube.com wss://*.chatgpt.com wss://*.chatgpt.com/; img-src 'self' * blob: data: https: https://docs.google.com https://drive-thirdparty.googleusercontent.com https://ssl.gstatic.com; style-src 'self' 'unsafe-inline' blob: chatgpt.com/ces https://*.chatgpt.com https://*.chatgpt.com/ https://*.oaistatic.com https://accounts.google.com/gsi/style https://chat.openai.com https://chatgpt.com https://chatgpt.com/ https://chatgpt.com/backend-anon https://chatgpt.com/backend-api https://chatgpt.com/backend/se https://chatgpt.com/public-api https://oaistatic.com https://snc.apps.openai.com wss://*.chatgpt.com wss://*.chatgpt.com/; font-src 'self' data: https://*.oaistatic.com https://cdn.openai.com https://fonts.gstatic.com; connect-src 'self' *.blob.core.windows.net *.oaiusercontent.com api.mapbox.com browser-intake-datadoghq.com chatgpt.com/ces events.mapbox.com https://*.chatgpt.com https://*.chatgpt.com/ https://*.oaistatic.com https://accounts.google.com https://analytics.tiktok.com https://api.atlassian.com https://api.oaistatsig.com https://api.onedrive.com https://api.stripe.com https://bat.bing.com https://bzr.openai.com https://cdn.openai.com/common/fonts/openai-sans/v2/openai-sans-regular.full.typeface.json https://cdn.openai.com/emojibase/ https://cdn.openai.com/pdf/ https://cdn.platform.openai.com https://chat.openai.com https://chatgpt.com https://chatgpt.com/ https://chatgpt.com/backend-anon https://chatgpt.com/backend-api https://chatgpt.com/backend/se https://chatgpt.com/public-api https://content.googleapis.com https://docs.google.com https://events.statsigapi.net https://featuregates.org https://graph.microsoft.com https://js.verygoodvault.com https://js3.verygoodvault.com https://oaistatic.com https://pixel-config.reddit.com https://production.plaid.com https://px.ads.linkedin.com/ https://realtime.chatgpt-staging.com https://realtime.chatgpt.com https://sandbox.plaid.com https://snc.apps.openai.com https://test-drive-20-1053047382554.us-central1.run.app https://transceiver.api.openai.com https://transceiver.api.openai.org https://vgs-collect-keeper.apps.verygood.systems https://www.googleadservices.com https://www.googleapis.com https://www.googletagmanager.com https://www.redditstatic.com statsigapi.net wss://*.chatgpt.com wss://*.chatgpt.com/ wss://*.webpubsub.azure.com; frame-src 'self' challenges.cloudflare.com https://*.embed.chatgpt.site https://*.js.stripe.com https://*.sharepoint.com https://*.web-sandbox.oaiusercontent.com https://*.withpersona.com https://504-SWE-347.mktoweb.com https://accounts.google.com/gsi https://accounts.google.com/gsi/iframe/select https://auth.openai.com https://cdn.openaimerge.com https://cdn.plaid.com https://cdn.platform.openai.com https://content.googleapis.com https://docs.google.com https://drive.google.com https://file-frame.oaistatic.com https://hooks.stripe.com https://js.stripe.com https://js.verygoodvault.com https://js3.verygoodvault.com https://mfe.prod.us-exp-api.experiancs.com https://mfe.uat.us-exp-api.experiancs.com https://onedrive.live.com https://services.sheerid.com https://web-sandbox.oaiusercontent.com js.stripe.com player.vimeo.com www.youtube.com; worker-src 'self' blob:; media-src 'self' *.oaiusercontent.com blob: https://cdn.oaistatic.com https://cdn.openai.com https://persistent.oaistatic.com; frame-ancestors 'self' chrome-extension://iaiigpefkbhgjcmcmffmfkpmhemdhdnj chrome-extension://lfkehkpjohcoelkpembgemeipeppanef; base-uri 'none'; report-to chatgpt-csp; report-uri https://chatgpt.com/ces/v1/telemetry/intake?ddsource=csp-report&dd-api-key=dummy-token";
        ContentSecurityPolicy csp = assertDoesNotThrow(() -> ContentSecurityPolicy.of(chatGptSecurityPolicy));
        assertNotNull(csp);
        assertEquals(14, csp.directives().size());
    }
}
