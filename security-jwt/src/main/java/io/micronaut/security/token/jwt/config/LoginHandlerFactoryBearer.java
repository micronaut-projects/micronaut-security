/*
 * Copyright 2017-2020 original authors
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

package io.micronaut.security.token.jwt.config;

import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.jwt.bearer.AccessRefreshTokenLoginHandler;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;

import javax.inject.Singleton;

/**
 * Instantiates a {@link Singleton} of {@link AccessRefreshTokenLoginHandler} if there is a bean of type {@link AccessRefreshTokenGenerator} and the condition {@link LoginHandlerFactoryBearerCondition} is fulfilled.
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(beans = AccessRefreshTokenGenerator.class)
@Requires(condition = LoginHandlerFactoryBearerCondition.class)
@Factory
public class LoginHandlerFactoryBearer {

    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;

    public LoginHandlerFactoryBearer(AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    /**
     *
     * @return a {@link LoginHandler} singleton of type {@link AccessRefreshTokenLoginHandler}.
     */
    @Singleton
    public LoginHandler createLoginHandler() {
        return new AccessRefreshTokenLoginHandler(accessRefreshTokenGenerator);
    }
}
