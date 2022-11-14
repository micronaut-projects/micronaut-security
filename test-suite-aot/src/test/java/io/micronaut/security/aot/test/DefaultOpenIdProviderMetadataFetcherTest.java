package io.micronaut.security.aot.test;

import io.micronaut.context.BeanContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
public class DefaultOpenIdProviderMetadataFetcherTest {

    @Inject
    BeanContext beanContext;

    @Test
    void defaultOpenIdProviderMetadataFetcherOptimizationsArePopulated() {
        assertTrue(beanContext.containsBean(OpenIdClientConfiguration.class));
        assertTrue(beanContext.containsBean(DefaultOpenIdProviderMetadataFetcher.class));
        //DefaultOpenIdProviderMetadataFetcher fetcher = beanContext.getBean(DefaultOpenIdProviderMetadataFetcher.class, Qualifiers.byName("cognito"));

    }
}
