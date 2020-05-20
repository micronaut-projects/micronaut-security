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

package io.micronaut.security.session;

import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;

import javax.inject.Singleton;

/**
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(condition = LoginHandlerFactorySessionCondition.class)
@Factory
public class LoginHandlerFactorySession {

    protected final RedirectConfiguration redirectConfiguration;
    protected final SessionStore<Session> sessionStore;
    protected final TokenConfiguration tokenConfiguration;

    /**
     *
     * @param redirectConfiguration Redirect configuration
     * @param sessionStore The session store
     * @param tokenConfiguration Token Configuration
     */
    public LoginHandlerFactorySession(RedirectConfiguration redirectConfiguration,
                                      SessionStore<Session> sessionStore,
                                      TokenConfiguration tokenConfiguration) {
        this.redirectConfiguration = redirectConfiguration;
        this.sessionStore = sessionStore;
        this.tokenConfiguration = tokenConfiguration;
    }

    /**
     *
     * @return a {@link LoginHandler} singleton of type {@link SessionLoginHandler}.
     */
    @Singleton
    public LoginHandler createLoginHandler() {
        return new SessionLoginHandler(redirectConfiguration, sessionStore, tokenConfiguration);
    }
}
