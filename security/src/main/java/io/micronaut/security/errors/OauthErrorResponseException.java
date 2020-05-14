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
package io.micronaut.security.errors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 *
 * An Runtime exception which implements {@link ErrorResponse}.
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
public class OauthErrorResponseException extends RuntimeException implements ErrorResponse {

    @NonNull
    private final ErrorCode errorCode;

    @Nullable
    private String errorDescription;

    @Nullable
    private String errorUri;


    /**
     *
     * @param errorCode the error code
     */
    public OauthErrorResponseException(@NonNull ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    /**
     *
     * @param errorCode The error code
     * @param errorDescription Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the errorCode that occurred.
     * @param errorUri URI identifying a human-readable web page with information about the errorCode
     */
    public OauthErrorResponseException(@NonNull ErrorCode errorCode,
                                       String errorDescription,
                                       String errorUri) {
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;

    }

    @NonNull
    @Override
    public ErrorCode getError() {
        return errorCode;
    }

    @Nullable
    @Override
    public String getErrorDescription() {
        return errorDescription;
    }

    @Nullable
    @Override
    public String getErrorUri() {
        return errorUri;
    }
}
