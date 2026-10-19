package io.micronaut.supabase.management;

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SupabaseManagementConfigurationPropertiesTest {

    @Test
    void propertiesAreBoundFromTheSupabaseManagementPrefix() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "supabase.management.url", "https://management.example.com",
            "supabase.management.access-token", "sbp_fixture_personal_access_token"))) {
            SupabaseManagementConfiguration configuration = context.getBean(SupabaseManagementConfiguration.class);

            assertEquals("https://management.example.com", configuration.getUrl());
            assertEquals("sbp_fixture_personal_access_token", configuration.getAccessToken());
        }
    }

    @Test
    void urlDefaultsToTheHostedManagementApiAndTheTokenIsOptional() {
        try (ApplicationContext context = ApplicationContext.run()) {
            SupabaseManagementConfiguration configuration = context.getBean(SupabaseManagementConfiguration.class);

            assertEquals("https://api.supabase.com", configuration.getUrl());
            assertNull(configuration.getAccessToken());
        }
    }

    @Test
    void trailingSlashOnUrlIsIgnored() {
        SupabaseManagementConfigurationProperties configuration = new SupabaseManagementConfigurationProperties();
        configuration.setUrl("https://management.example.com/");

        assertEquals("https://management.example.com", configuration.getUrl());
    }

    @Test
    void nullOrBlankUrlRestoresTheDefault() {
        SupabaseManagementConfigurationProperties configuration = new SupabaseManagementConfigurationProperties();
        configuration.setUrl("https://management.example.com");

        configuration.setUrl(null);
        assertEquals(SupabaseManagementConfiguration.DEFAULT_URL, configuration.getUrl());

        configuration.setUrl("https://management.example.com");
        configuration.setUrl("");
        assertEquals(SupabaseManagementConfiguration.DEFAULT_URL, configuration.getUrl());

        configuration.setUrl("https://management.example.com");
        configuration.setUrl("   ");
        assertEquals(SupabaseManagementConfiguration.DEFAULT_URL, configuration.getUrl());
    }

    @Test
    void interfaceDefaultsToTheHostedManagementApi() {
        SupabaseManagementConfiguration configuration = () -> null;

        assertEquals("https://api.supabase.com", configuration.getUrl());
        assertNull(configuration.getAccessToken());
    }
}
