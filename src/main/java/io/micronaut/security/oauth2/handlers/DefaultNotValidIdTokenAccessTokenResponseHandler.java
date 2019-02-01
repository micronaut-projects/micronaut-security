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

package io.micronaut.security.oauth2.handlers;

import io.micronaut.http.HttpResponse;
import io.micronaut.security.oauth2.openid.idtoken.IdTokenAccessTokenResponse;

import javax.inject.Singleton;

/**
 * Default implementation of {@link NotValidIdTokenAccessTokenResponseHandler}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class DefaultNotValidIdTokenAccessTokenResponseHandler implements NotValidIdTokenAccessTokenResponseHandler {

    @Override
    public HttpResponse<?> handle(IdTokenAccessTokenResponse idTokenAccessTokenResponse) {
        return HttpResponse.badRequest();
    }
}
