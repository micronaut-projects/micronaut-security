/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.endpoints.authorization.state.validation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.openid.endpoints.authorization.InvalidStateException;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.State;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.Optional;

/**
 * State validator implementation. Relies on a state persistence bean.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
@Requires(beans = StatePersistence.class)
@Singleton
public class DefaultStateValidator implements StateValidator {

    private final StatePersistence statePersistence;

    /**
     * @param statePersistence The state persistence bean
     */
    public DefaultStateValidator(StatePersistence statePersistence) {
        this.statePersistence = statePersistence;
    }

    @Override
    public void validate(@Nonnull HttpRequest<?> request, @Nullable State state) throws InvalidStateException {
        if (state == null) {
            throw new InvalidStateException("Provided state is null");
        }
        Optional<State> persistedState = statePersistence.retrieveState(request);
        if (!persistedState.isPresent()) {
            throw new InvalidStateException("Could not find the stored state");
        }
        if (!persistedState.get().equals(state)) {
            throw new InvalidStateException("State comparison failed");
        }
    }
}
