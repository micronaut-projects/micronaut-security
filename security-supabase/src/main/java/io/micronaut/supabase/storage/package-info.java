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
 * Declarative HTTP client and data models for the Supabase Storage REST API.
 *
 * <p>{@link io.micronaut.supabase.storage.SupabaseStorageClient} exposes the bucket, object, image
 * transformation, CDN and health routes of the API. The OpenAPI document declares almost every schema inline,
 * so each request and response body has a record of its own; the entities shared by several routes are
 * {@link io.micronaut.supabase.storage.BucketSchema}, {@link io.micronaut.supabase.storage.ObjectSchema} and
 * {@link io.micronaut.supabase.storage.ObjectInfoSchema}. The S3-compatible, Iceberg, vector and TUS resumable
 * upload routes are protocols of their own and are not part of this client.</p>
 *
 * @see <a href="https://supabase.github.io/storage/api.json">Supabase Storage API OpenAPI document</a>
 * @see <a href="https://supabase.com/docs/guides/storage">Supabase Storage</a>
 * @since 0.0.1
 */
@NullMarked
package io.micronaut.supabase.storage;

import org.jspecify.annotations.NullMarked;
