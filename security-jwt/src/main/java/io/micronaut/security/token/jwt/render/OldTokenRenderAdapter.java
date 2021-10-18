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

import io.micronaut.security.authentication.Authentication;

/**
 * Adapts from {@link io.micronaut.security.token.render.TokenRenderer} to {@link TokenRenderer}.
 * @author Sergio del Amo
 * @since 3.2.0
 */
public class OldTokenRenderAdapter implements TokenRenderer  {
    private final io.micronaut.security.token.render.TokenRenderer tokenRenderer;
    public OldTokenRenderAdapter(io.micronaut.security.token.render.TokenRenderer tokenRenderer) {
        this.tokenRenderer = tokenRenderer;
    }

    @Override
    public AccessRefreshToken render(Integer expiresIn, String accessToken, String refreshToken) {
        return new OldAccessRefreshTokenAdapter(tokenRenderer.render(expiresIn, accessToken, refreshToken));
    }

    @Override
    public AccessRefreshToken render(Authentication authentication, Integer expiresIn, String accessToken, String refreshToken) {
        return new OldAccessRefreshTokenAdapter(tokenRenderer.render(authentication, expiresIn, accessToken, refreshToken));
    }
}
