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
/**
 * Declarative HTTP client and data models for the Secrets resource of the Supabase Management API.
 *
 * <p>Project secrets are environment variables made available to the project's Edge Functions.
 * {@link io.micronaut.supabase.secrets.SupabaseSecretsClient} exposes the three routes of the resource:
 * listing, bulk creation and bulk deletion. {@link io.micronaut.supabase.secrets.SecretResponse} is the named
 * schema of the OpenAPI document; the item of the inline creation body has a record of its own,
 * {@link io.micronaut.supabase.secrets.CreateSecretRequest}.</p>
 *
 * @see <a href="https://supabase.com/docs/reference/api/introduction">Supabase Management API</a>
 * @see <a href="https://api.supabase.com/api/v1-json">Supabase Management API OpenAPI document</a>
 * @since 0.0.1
 */
@NullMarked
package io.micronaut.supabase.secrets;

import org.jspecify.annotations.NullMarked;
