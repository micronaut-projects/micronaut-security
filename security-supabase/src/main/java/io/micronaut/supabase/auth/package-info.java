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
 * Declarative HTTP client and data models for the Supabase Auth (GoTrue) REST API.
 *
 * <p>{@link io.micronaut.supabase.auth.SupabaseAuthClient} exposes every route of the API. Request bodies
 * whose schemas are inline in the OpenAPI document live in
 * {@link io.micronaut.supabase.auth.SupabaseAuthRequests}; named schemas have a record of their own.
 * Where the running server differs from the published OpenAPI document, the client follows the server
 * and documents the difference.</p>
 *
 * @see <a href="https://github.com/supabase/auth/blob/master/openapi.yaml">Supabase Auth REST API</a>
 * @since 0.0.1
 */
@NullMarked
package io.micronaut.supabase.auth;

import org.jspecify.annotations.NullMarked;
