/*
 * Copyright 2026 original authors
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
package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanProvider;
import io.micronaut.context.exceptions.NoSuchBeanException;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenIdProviderJwksSignatureConfigurationTest {
    private static final String JWKS_URI = "https://issuer.example/keys";
    private static final Duration BACKOFF = Duration.ofSeconds(10);

    @Test
    void metadataCreatedAtStartupIsUsedWithoutContactingTheProvider() {
        AtomicInteger calls = new AtomicInteger();
        List<Runnable> scheduled = new ArrayList<>();
        OpenIdProviderJwksSignatureConfiguration configuration = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", null, metadata(JWKS_URI), counting(calls, true), scheduled::add, BACKOFF);
        assertEquals("authserver", configuration.getName());
        assertNull(configuration.getKeyType(), "the key type must not be constrained");
        assertEquals(JWKS_URI, configuration.getUrl());
        assertEquals("https://issuer.example", configuration.getIssuer());
        assertEquals(0, calls.get());
        assertTrue(scheduled.isEmpty(), "nothing to resolve");
    }

    @Test
    void metadataNotCreatedAtStartupIsResolvedOnTheExecutorNeverOnTheCallingThread() {
        AtomicInteger calls = new AtomicInteger();
        List<Runnable> scheduled = new ArrayList<>();
        OpenIdProviderJwksSignatureConfiguration configuration = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", null, null, counting(calls, true), scheduled::add, BACKOFF);
        assertEquals(1, scheduled.size(), "the resolution is scheduled when the configuration is built");
        assertEquals(0, calls.get());

        for (int i = 0; i < 100; i++) {
            IllegalStateException e = assertThrows(IllegalStateException.class, configuration::getUrl);
            assertTrue(e.getMessage().contains("authserver"));
            assertNull(configuration.getIssuer());
        }
        assertEquals(0, calls.get(), "the provider is never contacted on the calling thread");
        assertEquals(1, scheduled.size(), "a single resolution is in flight");

        scheduled.get(0).run();
        assertEquals(1, calls.get());
        assertEquals(JWKS_URI, configuration.getUrl());
        assertEquals("https://issuer.example", configuration.getIssuer());
        assertEquals(JWKS_URI, configuration.getUrl());
        assertEquals(1, calls.get(), "the metadata is memoized");
    }

    @Test
    void issuerAssertedByTheMetadataIsPreferredOverTheConfiguredIssuer() {
        OpenIdProviderJwksSignatureConfiguration configured = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", "https://configured.example", metadata(JWKS_URI), failing(), Runnable::run, BACKOFF);
        assertEquals("https://issuer.example", configured.getIssuer());
    }

    @Test
    void configuredIssuerIsUsedWhenTheMetadataAssertsNone() {
        DefaultOpenIdProviderMetadata metadata = metadata(JWKS_URI);
        metadata.setIssuer(null);
        OpenIdProviderJwksSignatureConfiguration configured = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", "https://configured.example", metadata, failing(), Runnable::run, BACKOFF);
        assertEquals("https://configured.example", configured.getIssuer());
        OpenIdProviderJwksSignatureConfiguration unbound = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", null, metadata, failing(), Runnable::run, BACKOFF);
        assertNull(unbound.getIssuer());
    }

    @Test
    void issuerIsTheConfiguredIssuerWhileTheMetadataIsUnavailable() {
        List<Runnable> scheduled = new ArrayList<>();
        OpenIdProviderJwksSignatureConfiguration configured = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", "https://configured.example", null, failing(), scheduled::add, BACKOFF);
        assertEquals("https://configured.example", configured.getIssuer());
        assertThrows(IllegalStateException.class, configured::getUrl, "the url cannot be resolved, so no token is verified");
        scheduled.forEach(Runnable::run);
        assertEquals("https://configured.example", configured.getIssuer());
        assertThrows(IllegalStateException.class, configured::getUrl);
    }

    @Test
    void providerWithoutJwksUriFails() {
        OpenIdProviderJwksSignatureConfiguration configuration = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", null, metadata(null), failing(), Runnable::run, BACKOFF);
        assertThrows(IllegalStateException.class, configuration::getUrl);
    }

    @Test
    void failuresAreBackedOffAndNeverResolvedOnTheCallingThread() {
        List<Runnable> scheduled = new ArrayList<>();
        AtomicInteger calls = new AtomicInteger();
        AtomicLong now = new AtomicLong();
        boolean[] available = {false};
        BeanProvider<DefaultOpenIdProviderMetadata> provider = () -> {
            calls.incrementAndGet();
            if (!available[0]) {
                throw new NoSuchBeanException(DefaultOpenIdProviderMetadata.class);
            }
            return metadata(JWKS_URI);
        };
        OpenIdProviderJwksSignatureConfiguration configuration = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", null, null, provider, scheduled::add, Duration.ofSeconds(10), now::get);
        assertEquals(1, scheduled.size(), "the first resolution is scheduled when the configuration is built");
        assertEquals(0, calls.get());

        scheduled.get(0).run();
        assertEquals(1, calls.get());
        for (int i = 0; i < 100; i++) {
            assertThrows(IllegalStateException.class, configuration::getUrl);
        }
        assertEquals(1, calls.get(), "the provider is not contacted during the back-off");
        assertEquals(1, scheduled.size(), "no resolution is scheduled during the back-off");

        now.set(Duration.ofSeconds(10).toNanos());
        for (int i = 0; i < 100; i++) {
            assertThrows(IllegalStateException.class, configuration::getUrl);
        }
        assertEquals(2, scheduled.size(), "a single resolution once the back-off elapsed");
        assertEquals(1, calls.get(), "callers never contact the provider themselves");

        scheduled.get(1).run();
        assertEquals(2, calls.get());
        for (int i = 0; i < 100; i++) {
            assertThrows(IllegalStateException.class, configuration::getUrl);
        }
        assertEquals(2, scheduled.size(), "a failed resolution starts a new back-off");

        available[0] = true;
        now.set(Duration.ofSeconds(20).toNanos());
        assertThrows(IllegalStateException.class, configuration::getUrl);
        assertEquals(3, scheduled.size());
        scheduled.get(2).run();
        assertEquals(JWKS_URI, configuration.getUrl());
        int callsAfterResolution = calls.get();
        assertEquals(JWKS_URI, configuration.getUrl());
        assertEquals(callsAfterResolution, calls.get(), "the resolved metadata is memoized");
    }

    @Test
    void zeroBackoffSchedulesAtMostOneResolutionAtATime() {
        List<Runnable> scheduled = new ArrayList<>();
        AtomicInteger calls = new AtomicInteger();
        OpenIdProviderJwksSignatureConfiguration configuration = new OpenIdProviderJwksSignatureConfiguration(
            "authserver", null, null, counting(calls, false), scheduled::add, Duration.ZERO, () -> 0L);
        assertEquals(1, scheduled.size());
        for (int i = 0; i < 100; i++) {
            assertThrows(IllegalStateException.class, configuration::getUrl);
        }
        assertEquals(0, calls.get(), "callers never contact the provider");
        assertEquals(1, scheduled.size(), "a single resolution is in flight at a time");
        scheduled.get(0).run();
        assertEquals(1, calls.get());
        assertThrows(IllegalStateException.class, configuration::getUrl);
        assertEquals(2, scheduled.size(), "without back-off the next call schedules the next resolution");
    }

    private static BeanProvider<DefaultOpenIdProviderMetadata> counting(AtomicInteger calls, boolean available) {
        return () -> {
            calls.incrementAndGet();
            if (!available) {
                throw new NoSuchBeanException(DefaultOpenIdProviderMetadata.class);
            }
            return metadata(JWKS_URI);
        };
    }

    private static BeanProvider<DefaultOpenIdProviderMetadata> failing() {
        return () -> {
            throw new NoSuchBeanException(DefaultOpenIdProviderMetadata.class);
        };
    }

    private static DefaultOpenIdProviderMetadata metadata(String jwksUri) {
        DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata("authserver");
        metadata.setJwksUri(jwksUri);
        metadata.setIssuer("https://issuer.example");
        return metadata;
    }
}
