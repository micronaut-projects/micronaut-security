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

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ContentSecurityPolicyTest {

    @Test
    void copiesTheDirectivesDefensively() {
        List<ContentSecurityPolicyDirective> directives = new ArrayList<>();
        directives.add(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"));
        ContentSecurityPolicy policy = new ContentSecurityPolicy(directives);

        directives.add(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'self'"));

        assertEquals("default-src 'none'", policy.toHeaderValue());
        assertThrows(UnsupportedOperationException.class, () -> policy.directives().add(directives.get(1)));
    }

    @Test
    void toStringRedactsTheNonceThatTheHeaderValueCarries() {
        ContentSecurityPolicy policy = new ContentSecurityPolicy(List.of(
            new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"),
            new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-abc123' 'strict-dynamic'")));

        assertEquals("default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'", policy.toHeaderValue());
        assertEquals("default-src 'none'; script-src 'nonce-[redacted]' 'strict-dynamic'", policy.toString());
    }

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
    void parsesEdgeCasesOfTheHeaderSyntax() {
        ContentSecurityPolicy csp = ContentSecurityPolicy.of(
            " ;default-src   'self'  ;; SCRIPT-SRC 'nonce-abc' https://cdn.example.com; script-src 'none'; upgrade-insecure-requests ; ");

        assertNotNull(csp);
        assertEquals(List.of(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'self'"),
                new ContentSecurityPolicyDirective("SCRIPT-SRC", "'nonce-abc' https://cdn.example.com"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS, null)),
            csp.directives(), "empty components are dropped, names and values are kept as received");
        assertEquals(List.of("'self'"), csp.defaultSrc().values());
        assertEquals(new ContentSecurityPolicyDirective("SCRIPT-SRC", "'nonce-abc' https://cdn.example.com"), csp.scriptSrc(),
            "directive names are case-insensitive and the first of duplicate directives applies, as in user agents");
    }
}
