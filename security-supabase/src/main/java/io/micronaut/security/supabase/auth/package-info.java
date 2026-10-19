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
 * Integration between Micronaut Security and Supabase Auth.
 *
 * <p>Classes in this package adapt the Supabase Auth data models of {@code io.micronaut.supabase.auth} to the
 * Micronaut Security contracts and plug Supabase into the login, refresh and logout flows:</p>
 * <ul>
 *   <li>{@link io.micronaut.security.supabase.auth.SupabaseAuthenticationProvider} signs users in with the
 *   password grant.</li>
 *   <li>{@link io.micronaut.security.supabase.auth.AuthenticationAccessTokenResponseSchemaAdapter} carries the
 *   Supabase tokens, so cookie and bearer login handlers hand them to the client instead of minting their
 *   own.</li>
 *   <li>{@link io.micronaut.security.supabase.auth.SupabaseRefreshTokenPersistence} and
 *   {@link io.micronaut.security.supabase.auth.SupabaseRefreshTokenValidator} back the
 *   {@code /oauth/access_token} endpoint with the refresh-token grant.</li>
 *   <li>{@link io.micronaut.security.supabase.auth.SupabaseTokenCookieClearerLogoutHandler} revokes the Supabase
 *   session when the token cookies are cleared.</li>
 *   <li>{@link io.micronaut.security.supabase.auth.AuthenticationUserSchemaAdapter} exposes a
 *   {@link io.micronaut.supabase.auth.UserSchema} as an
 *   {@link io.micronaut.security.authentication.Authentication}.</li>
 * </ul>
 *
 * @since 0.0.1
 */
@NullMarked
package io.micronaut.security.supabase.auth;

import org.jspecify.annotations.NullMarked;
