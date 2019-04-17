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

package io.micronaut.security.oauth2.responses;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.State;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateSerDes;

import javax.annotation.Nullable;
import java.util.function.Supplier;

/**
 * Base class to extend from that handles state retrieval and caching.
 *
 * @author James Kleeh
 * @since 1.1.0
 */
@Internal
public abstract class AbstractAuthenticationResponse implements AuthenticationResponse {

    private final Supplier<State> stateSupplier;

    /**
     * @param stateSerDes The state serdes
     */
    public AbstractAuthenticationResponse(StateSerDes stateSerDes) {
        this.stateSupplier = SupplierUtil.memoized(() -> {
            String state = getStateValue();
            if (state != null) {
                return stateSerDes.deserialize(state);
            } else {
                return null;
            }
        });
    }

    /**
     * @return The state string value
     */
    @Nullable
    protected abstract String getStateValue();

    @Nullable
    @Override
    public State getState() {
        return stateSupplier.get();
    }
}
