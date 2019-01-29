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

import io.micronaut.security.oauth2.openid.endpoints.EndpointUrl;

import javax.annotation.Nonnull;
import java.util.List;

/**
 * End-session endpoint configuration.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public interface EndSessionEndpointConfiguration extends EndpointUrl {

    /**
     *
     * @return End-session endpoint parameters.
     */
    @Nonnull
    List<EndSessionParameter> getParameters();
}
