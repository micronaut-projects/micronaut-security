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
package io.micronaut.supabase.secrets;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.supabase.management.SupabaseManagementConfiguration;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Declarative client for the Secrets resource of the Supabase Management API.
 *
 * <p>Set {@code supabase.management.access-token} to a personal access token, and
 * {@link io.micronaut.supabase.management.SupabaseManagementDiscoveryClient} resolves the client to the hosted
 * Management API at {@value SupabaseManagementConfiguration#DEFAULT_URL}. The token is added to every request
 * by {@link io.micronaut.supabase.management.SupabaseManagementAccessTokenClientFilter}; a personal access
 * token needs no scope, an OAuth token needs {@code secrets:read} to list and {@code secrets:write} to create
 * or delete. Set {@code micronaut.http.services.supabase-management.url} to address another server, which takes
 * precedence over {@code supabase.management.url}.</p>
 *
 * <p>Every route is addressed by the project reference, the twenty-letter subdomain of a hosted project.
 * The Management API allows {@code 120} requests per minute per token and rejects requests beyond that with
 * {@code 429}. Rejected requests surface as
 * {@link io.micronaut.http.client.exceptions.HttpClientResponseException}, except {@code 404} responses, which
 * the methods return as-is. The OpenAPI document declares no body for error responses. When Micronaut
 * Validation is on the classpath, parameters are validated before the request is sent: reserved names,
 * oversized values, empty bodies and more than {@value #MAX_SECRETS_PER_REQUEST} secrets fail with a
 * {@link jakarta.validation.ConstraintViolationException} without reaching the API.</p>
 *
 * @see <a href="https://supabase.com/docs/reference/api/v1-list-all-secrets">Supabase Management API: Secrets</a>
 * @since 0.0.1
 */
@Experimental
@Client(id = SupabaseManagementConfiguration.SERVICE_ID, path = SupabaseSecretsClient.PROJECTS_PATH)
public interface SupabaseSecretsClient {

    /**
     * Path of the projects resource below the Management API URL.
     */
    String PROJECTS_PATH = "/v1/projects";

    /**
     * Maximum number of secrets created in a single request.
     */
    int MAX_SECRETS_PER_REQUEST = 100;

    /**
     * Lists every secret of a project, values included.
     *
     * @param ref Project reference
     * @return The project's secrets
     * @since 0.0.1
     */
    @Get("/{ref}/secrets")
    HttpResponse<List<SecretResponse>> list(@PathVariable("ref") @NotBlank String ref);

    /**
     * Creates up to {@value #MAX_SECRETS_PER_REQUEST} secrets, replacing the values of those that already exist.
     *
     * @param ref Project reference
     * @param secrets Secrets to create
     * @return The upstream response, {@code 201} on success
     * @since 0.0.1
     */
    @Post("/{ref}/secrets")
    HttpResponse<?> create(@PathVariable("ref") @NotBlank String ref,
                           @Body @NotEmpty @Size(max = MAX_SECRETS_PER_REQUEST) List<@Valid CreateSecretRequest> secrets);

    /**
     * Deletes the secrets with the given names.
     *
     * @param ref Project reference
     * @param names Names of the secrets to delete
     * @return The upstream response, {@code 200} on success
     * @since 0.0.1
     */
    @Delete("/{ref}/secrets")
    HttpResponse<?> delete(@PathVariable("ref") @NotBlank String ref,
                           @Body @NotEmpty List<@NotBlank String> names);
}
