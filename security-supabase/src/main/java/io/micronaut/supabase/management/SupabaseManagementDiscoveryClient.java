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
package io.micronaut.supabase.management;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.discovery.DiscoveryClient;
import io.micronaut.discovery.ServiceInstance;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;

import java.net.URI;
import java.util.List;

/**
 * Resolves the {@code supabase-management} service to the Management API URL.
 *
 * <p>The declarative clients look the {@code supabase-management} service id up through service discovery
 * whenever {@code micronaut.http.services.supabase-management.url} is not set. This client answers that
 * lookup from {@link SupabaseManagementConfiguration#getUrl()}, which defaults to the hosted Management API,
 * so no HTTP client configuration is needed. An explicit {@code micronaut.http.services.supabase-management.url}
 * takes precedence, and other {@code micronaut.http.services.supabase-management.*} settings combine with the
 * discovered URL.</p>
 *
 * @since 0.0.1
 */
@Experimental
@Singleton
@Requires(classes = DiscoveryClient.class)
@Requires(beans = SupabaseManagementConfiguration.class)
public class SupabaseManagementDiscoveryClient implements DiscoveryClient {

    private final SupabaseManagementConfiguration configuration;

    /**
     * Creates the discovery client.
     *
     * @param configuration Management API configuration
     */
    public SupabaseManagementDiscoveryClient(SupabaseManagementConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public Publisher<List<ServiceInstance>> getInstances(String serviceId) {
        if (!SupabaseManagementConfiguration.SERVICE_ID.equals(serviceId)) {
            return Publishers.just(List.of());
        }
        return Publishers.just(List.of(ServiceInstance.of(SupabaseManagementConfiguration.SERVICE_ID, URI.create(configuration.getUrl()))));
    }

    @Override
    public Publisher<List<String>> getServiceIds() {
        return Publishers.just(List.of(SupabaseManagementConfiguration.SERVICE_ID));
    }

    @Override
    public String getDescription() {
        return "Supabase Management API";
    }

    @Override
    public void close() {
        // nothing to release
    }
}
