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
 * Configuration shared by the clients of the Supabase Management API: the API URL, the personal access token
 * and the client filter that sends it.
 *
 * <p>The Management API at {@code https://api.supabase.com} administers Supabase projects and organizations.
 * Unlike the project APIs it is not addressed by project URL and not authorized by the project API keys, but by
 * a personal access token or an OAuth 2.0 token. Clients of its resources, such as
 * {@link io.micronaut.supabase.secrets.SupabaseSecretsClient}, share the {@code supabase-management} service
 * id so that this configuration applies to all of them.</p>
 *
 * @see <a href="https://supabase.com/docs/reference/api/introduction">Supabase Management API</a>
 * @since 0.0.1
 */
@NullMarked
package io.micronaut.supabase.management;

import org.jspecify.annotations.NullMarked;
