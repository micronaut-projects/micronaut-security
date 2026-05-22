/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.websockets;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.bind.ArgumentBinder;
import io.micronaut.core.convert.ArgumentConversionContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.utils.SecurityBindingResultUtils;
import io.micronaut.websocket.bind.WebSocketState;
import io.micronaut.websocket.bind.WebSocketStateBinder;
import jakarta.inject.Singleton;

/**
 * {@link WebSocketStateBinder} implementation for {@link Authentication}.
 */
@Requires(classes = WebSocketStateBinder.class)
@Singleton
public final class AuthenticationWebSocketStateBinder implements WebSocketStateBinder<Authentication> {

    @Override
    public ArgumentBinder.BindingResult<Authentication> bind(ArgumentConversionContext<Authentication> context,
                                                WebSocketState source) {
        return SecurityBindingResultUtils.authentication(source.getOriginatingRequest(), Authentication.class);
    }
}
