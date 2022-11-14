package io.micronaut.security.aot.test;

import io.micronaut.context.BeanContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class DefaultOpenIdProviderMetadataFetcherTest {

    @Inject
    BeanContext beanContext;

    @EnabledIfEnvironmentVariable(named = "AUTH_SERVER_A", matches = "http://localhost:8081")
    @Test
    void defaultOpenIdProviderMetadataFetcherOptimizationsArePopulated() {
        assertTrue(beanContext.containsBean(OpenIdClientConfiguration.class));
        assertTrue(beanContext.containsBean(OpenIdProviderMetadataFetcher.class));
        OpenIdProviderMetadataFetcher openIdProviderMetadataFetcher = beanContext.getBean(OpenIdProviderMetadataFetcher.class);
        assertTrue(openIdProviderMetadataFetcher instanceof DefaultOpenIdProviderMetadataFetcher);
        assertTrue(beanContext.containsBean(OpenIdProviderMetadataFetcher.class, Qualifiers.byName("cognito")));
        openIdProviderMetadataFetcher = beanContext.getBean(OpenIdProviderMetadataFetcher.class);
        assertTrue(openIdProviderMetadataFetcher instanceof DefaultOpenIdProviderMetadataFetcher);
        assertTrue(DefaultOpenIdProviderMetadataFetcher.OPTIMIZATIONS.findMetadata("cognito").isPresent());
        assertFalse(DefaultOpenIdProviderMetadataFetcher.OPTIMIZATIONS.findMetadata("foo").isPresent());
        //assertTrue(beanContext.containsBean(DefaultOpenIdProviderMetadataFetcher.class));
    }
}
