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
package io.micronaut.supabase;

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
 * Resolves the {@code supabase} service to the project URL.
 *
 * <p>The declarative client looks the {@code supabase} service id up through service discovery whenever
 * {@code micronaut.http.services.supabase.url} is not set. This client answers that lookup from
 * {@code supabase.url} or {@code supabase.project-id}, so a hosted project needs no HTTP client configuration.
 * The Auth API path is not part of the instance: the client carries it as its context path, taken from
 * {@code supabase.auth-path}. An explicit {@code micronaut.http.services.supabase.url} takes precedence, and
 * other {@code micronaut.http.services.supabase.*} settings such as {@code follow-redirects} combine with the
 * discovered URL.</p>
 *
 * @since 0.0.1
 */
@Experimental
@Singleton
@Requires(classes = DiscoveryClient.class)
@Requires(condition = SupabaseProjectConfiguredCondition.class)
public class SupabaseDiscoveryClient implements DiscoveryClient {

    private final SupabaseConfiguration configuration;

    /**
     * Creates the discovery client.
     *
     * @param configuration Supabase project configuration
     */
    public SupabaseDiscoveryClient(SupabaseConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public Publisher<List<ServiceInstance>> getInstances(String serviceId) {
        if (!SupabaseApiKeyClientFilter.SERVICE_ID.equals(serviceId)) {
            return Publishers.just(List.of());
        }
        return Publishers.just(configuration.getProjectUrl()
            .map(url -> List.of(ServiceInstance.of(SupabaseApiKeyClientFilter.SERVICE_ID, URI.create(url))))
            .orElseGet(List::of));
    }

    @Override
    public Publisher<List<String>> getServiceIds() {
        return Publishers.just(configuration.getProjectUrl().isPresent() ? List.of(SupabaseApiKeyClientFilter.SERVICE_ID) : List.of());
    }

    @Override
    public String getDescription() {
        return "Supabase";
    }

    @Override
    public void close() {
        // nothing to release
    }
}
