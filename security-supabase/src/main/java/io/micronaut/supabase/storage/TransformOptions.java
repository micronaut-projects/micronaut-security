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
package io.micronaut.supabase.storage;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

/**
 * Image transformation applied when an object is served, as embedded in {@link SignObjectRequest}.
 *
 * <p>The same options are query parameters of the {@code /render/image/**} routes. Image transformation
 * must be enabled on the server; the hosted platform offers it on paid plans.</p>
 *
 * @param height Height in pixels
 * @param width Width in pixels
 * @param resize Resize mode, {@code cover}, {@code contain} or {@code fill}
 * @param format Output format, {@code origin}, {@code avif} or {@code webp}
 * @param quality Output quality from 20 to 100
 * @param gravity Crop gravity: a compass direction such as {@code no} or {@code soea}, {@code ce} for center,
 *                {@code sm} for smart or {@code fp} for a focal point given by the offsets
 * @param xOffset Horizontal gravity offset; relative below 1, absolute pixels from 1
 * @param yOffset Vertical gravity offset; relative below 1, absolute pixels from 1
 * @since 0.0.1
 */
@Serdeable
@Experimental
public record TransformOptions(
    @Nullable Integer height,
    @Nullable Integer width,
    @Nullable String resize,
    @Nullable String format,
    @Nullable Integer quality,
    @Nullable String gravity,
    @JsonProperty("x_offset") @Nullable Double xOffset,
    @JsonProperty("y_offset") @Nullable Double yOffset
) {
}
