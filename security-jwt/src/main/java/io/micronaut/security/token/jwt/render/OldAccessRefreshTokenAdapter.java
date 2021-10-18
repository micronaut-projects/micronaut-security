/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.jwt.render;

import io.micronaut.core.annotation.Internal;

/**
 * Adapts from {@link io.micronaut.security.token.render.AccessRefreshToken} to {@link AccessRefreshToken}.
 * @since 3.2.0
 * @author Sergio del Amo
 */
@Deprecated
@Internal
public class OldAccessRefreshTokenAdapter extends AccessRefreshToken {

    public OldAccessRefreshTokenAdapter(io.micronaut.security.token.render.AccessRefreshToken accessRefreshToken) {
        super(accessRefreshToken.getAccessToken(), accessRefreshToken.getRefreshToken(), accessRefreshToken.getTokenType(), accessRefreshToken.getExpiresIn());
    }
}
