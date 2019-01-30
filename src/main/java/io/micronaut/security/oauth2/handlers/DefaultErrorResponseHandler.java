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

package io.micronaut.security.oauth2.handlers;

import io.micronaut.context.annotation.Secondary;
import io.micronaut.http.HttpResponse;
import io.micronaut.security.oauth2.responses.ErrorResponse;
import io.micronaut.security.oauth2.responses.Oauth2ErrorResponse;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.inject.Singleton;

/**
 * Default implementation of {@link ErrorResponseHandler}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Secondary
@Singleton
public class DefaultErrorResponseHandler implements ErrorResponseHandler {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultErrorResponseHandler.class);

    @Override
    public Single<HttpResponse> handle(ErrorResponse errorResponse) {
        logErrorResponse(errorResponse);
        Oauth2ErrorResponse body = Oauth2ErrorResponse.of(errorResponse);
        return Single.just(HttpResponse.badRequest(body));
    }

    /**
     * Logs the Error Response.
     * @param errorResponse Error Response.
     */
    protected void logErrorResponse(ErrorResponse errorResponse) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("error: {} error_description: {}, state: {} error_uri {}",
                    errorResponse.getError(),
                    errorResponse.getErrorDescription() != null ? errorResponse.getErrorDescription() : "",
                    errorResponse.getErrorUri() != null ? errorResponse.getErrorUri() : "",
                    errorResponse.getState() != null ? errorResponse.getState() : "");
        }
    }
}
