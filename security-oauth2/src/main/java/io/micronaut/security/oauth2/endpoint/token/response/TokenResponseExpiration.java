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
package io.micronaut.security.oauth2.endpoint.token.response;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.annotation.Introspected;

import java.util.Calendar;
import java.util.Date;

/**
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Introspected
public class TokenResponseExpiration extends TokenResponse {

    @Nullable
    private Date expiration;

    /**
     *
     * @param tokenResponse Token Response
     */
    public TokenResponseExpiration(TokenResponse tokenResponse) {
        setAccessToken(tokenResponse.getAccessToken());
        setRefreshToken(tokenResponse.getRefreshToken());
        setExpiresIn(tokenResponse.getExpiresIn());
        setScope(tokenResponse.getScope());
        setTokenType(tokenResponse.getTokenType());
    }

    /**
     * Populates Expiration date with the expires in value.
     *
     * @param expiresIn The lifetime in seconds of the access token.
     */
    @Override
    public void setExpiresIn(Integer expiresIn) {
        super.setExpiresIn(expiresIn);

        if (expiresIn != null) {
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.SECOND, expiresIn);
            this.expiration = calendar.getTime();
        }
    }

    /**
     *
     * @return Expiration date of the access token. Calculated with the expires in recevied by the authorization server.
     */
    @Nullable
    public Date getExpiration() {
        return expiration;
    }
}
