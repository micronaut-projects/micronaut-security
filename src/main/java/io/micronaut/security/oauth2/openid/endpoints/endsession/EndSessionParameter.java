/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.openid.endpoints.endsession;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Utility class to enable the configuration of url parameters send to the
 * end-session endpoint exposed by OpenID providers.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class EndSessionParameter {
    @Nonnull
    private String name;

    @Nullable
    private String value;

    @Nonnull
    private EndSessionParameterType type = EndSessionParameterType.STRING;

    /**
     * EndSessionParameter empty constructor.
     */
    public EndSessionParameter() {
    }

    /**
     *
     * @return Parameter name
     */
    @Nonnull
    public String getName() {
        return name;
    }

    /**
     *
     * @param name Parameter name
     */
    public void setName(@Nonnull String name) {
        this.name = name;
    }

    /**
     *
     * @return The parameter value
     */
    @Nullable
    public String getValue() {
        return value;
    }

    /**
     *
     * @param value The parameter value
     */
    public void setValue(@Nullable String value) {
        this.value = value;
    }

    /**
     *
     * @return The parameter type
     */
    @Nonnull
    public EndSessionParameterType getType() {
        return type;
    }

    /**
     * Sets the parameter type. Defaults to String.
     * @param type parameter type
     */
    public void setType(@Nonnull EndSessionParameterType type) {
        this.type = type;
    }
}
