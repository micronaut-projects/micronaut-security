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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import javax.annotation.Nullable;
import java.net.URI;

/**
 * Allows to restore the previous state of the application, other use of state parameter is to mitigate CSRF attacks.
 * @author James Kleeh
 * @since 1.0.0
 */
public interface State {

    /**
     *
     * @return Original URI which caused the authorization request to be triggered.
     */
    @Nullable
    URI getOriginalUri();
}
