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
 * Protects HTTP endpoints using the browser-provided
 * <a href="https://www.w3.org/TR/fetch-metadata/">Fetch Metadata request headers</a>.
 *
 * <p>Fetch Metadata is a request-isolation signal and does not replace authentication,
 * authorization, or CSRF protection. Routes annotated with {@code @CrossOrigin} are exempted
 * only when their CORS configuration accepts the request origin and HTTP method.</p>
 *
 * @since 5.4.0
 */
@Configuration
@NullMarked
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Configuration;
import org.jspecify.annotations.NullMarked;
