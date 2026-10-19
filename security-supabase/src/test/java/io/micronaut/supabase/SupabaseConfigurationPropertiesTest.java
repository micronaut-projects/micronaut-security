package io.micronaut.supabase;

import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SupabaseConfigurationPropertiesTest {

    @Test
    void propertiesAreBoundFromTheSupabasePrefix() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "supabase.url", "https://api.example.com",
            "supabase.project-id", "abcdefghijklmnopqrst",
            "supabase.publishable-key", "sb_publishable_fixture",
            "supabase.secret-key", "sb_secret_fixture"))) {
            SupabaseConfiguration configuration = context.getBean(SupabaseConfiguration.class);

            assertEquals("https://api.example.com", configuration.getUrl());
            assertEquals("abcdefghijklmnopqrst", configuration.getProjectId());
            assertEquals("sb_publishable_fixture", configuration.getPublishableKey());
            assertEquals("sb_secret_fixture", configuration.getSecretKey());
        }
    }

    @Test
    void everyPropertyIsOptional() {
        try (ApplicationContext context = ApplicationContext.run()) {
            SupabaseConfiguration configuration = context.getBean(SupabaseConfiguration.class);

            assertNull(configuration.getUrl());
            assertNull(configuration.getProjectId());
            assertNull(configuration.getPublishableKey());
            assertNull(configuration.getSecretKey());
            assertTrue(configuration.getProjectUrl().isEmpty());
            assertTrue(configuration.getAuthUrl().isEmpty());
            assertTrue(configuration.getStorageUrl().isEmpty());
        }
    }

    @Test
    void projectIdDerivesTheHostedUrl() {
        SupabaseConfigurationProperties configuration = new SupabaseConfigurationProperties();
        configuration.setProjectId("abcdefghijklmnopqrst");

        assertEquals(Optional.of("https://abcdefghijklmnopqrst.supabase.co"), configuration.getProjectUrl());
        assertEquals(Optional.of("https://abcdefghijklmnopqrst.supabase.co/auth/v1"), configuration.getAuthUrl());
    }

    @Test
    void urlTakesPrecedenceOverProjectId() {
        SupabaseConfigurationProperties configuration = new SupabaseConfigurationProperties();
        configuration.setProjectId("abcdefghijklmnopqrst");
        configuration.setUrl("https://api.example.com");

        assertEquals(Optional.of("https://api.example.com"), configuration.getProjectUrl());
        assertEquals(Optional.of("https://api.example.com/auth/v1"), configuration.getAuthUrl());
    }

    @Test
    void authPathDefaultsToAuthV1AndCanBeEmptied() {
        SupabaseConfigurationProperties configuration = new SupabaseConfigurationProperties();
        configuration.setUrl("https://api.example.com");
        assertEquals("/auth/v1", configuration.getAuthPath());
        assertEquals(Optional.of("https://api.example.com/auth/v1"), configuration.getAuthUrl());

        configuration.setAuthPath("");
        assertEquals(Optional.of("https://api.example.com"), configuration.getAuthUrl());
    }

    @Test
    void storagePathDefaultsToStorageV1AndCanBeEmptied() {
        SupabaseConfigurationProperties configuration = new SupabaseConfigurationProperties();
        configuration.setUrl("https://api.example.com");
        assertEquals("/storage/v1", configuration.getStoragePath());
        assertEquals(Optional.of("https://api.example.com/storage/v1"), configuration.getStorageUrl());

        configuration.setStoragePath("");
        assertEquals(Optional.of("https://api.example.com"), configuration.getStorageUrl());

        configuration.setStoragePath(null);
        assertEquals("", configuration.getStoragePath());
    }

    @Test
    void storagePathIsBoundFromTheSupabasePrefix() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.storage-path", ""))) {
            assertEquals("", context.getBean(SupabaseConfiguration.class).getStoragePath());
        }
    }

    @Test
    void interfaceDefaultsResolveTheStorageUrl() {
        SupabaseConfiguration configuration = new SupabaseConfiguration() {
            @Override
            public String getUrl() {
                return "https://api.example.com";
            }

            @Override
            public String getProjectId() {
                return null;
            }

            @Override
            public String getPublishableKey() {
                return null;
            }

            @Override
            public String getSecretKey() {
                return null;
            }
        };

        assertEquals("/storage/v1", configuration.getStoragePath());
        assertEquals(Optional.of("https://api.example.com/storage/v1"), configuration.getStorageUrl());
    }

    @Test
    void authPathIsBoundFromTheSupabasePrefix() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("supabase.auth-path", ""))) {
            assertEquals("", context.getBean(SupabaseConfiguration.class).getAuthPath());
        }
    }

    @Test
    void trailingSlashOnUrlIsIgnored() {
        SupabaseConfigurationProperties configuration = new SupabaseConfigurationProperties();
        configuration.setUrl("https://api.example.com/");

        assertEquals(Optional.of("https://api.example.com/auth/v1"), configuration.getAuthUrl());
    }

    @Test
    void blankUrlFallsBackToProjectId() {
        SupabaseConfigurationProperties configuration = new SupabaseConfigurationProperties();
        configuration.setUrl("  ");
        configuration.setProjectId("abcdefghijklmnopqrst");

        assertEquals(Optional.of("https://abcdefghijklmnopqrst.supabase.co"), configuration.getProjectUrl());
    }
}
