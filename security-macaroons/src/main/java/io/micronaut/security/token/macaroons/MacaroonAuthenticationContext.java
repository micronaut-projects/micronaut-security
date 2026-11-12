/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.token.macaroons;

import java.util.List;
import java.util.Map;

/**
 * Signature-verified Macaroon data used to build an authentication.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public final class MacaroonAuthenticationContext {

    private final String location;
    private final String identifier;
    private final MacaroonSerialization serialization;
    private final Map<String, Object> claims;
    private final List<MacaroonCaveat> caveats;

    /**
     * @param location The Macaroon location
     * @param identifier The Macaroon identifier
     * @param serialization The matched serialization
     * @param claims Claims decoded from verified first-party caveats
     * @param caveats First-party caveats
     */
    public MacaroonAuthenticationContext(String location,
                                         String identifier,
                                         MacaroonSerialization serialization,
                                         Map<String, Object> claims,
                                         List<MacaroonCaveat> caveats) {
        this.location = location;
        this.identifier = identifier;
        this.serialization = serialization;
        this.claims = Map.copyOf(claims);
        this.caveats = List.copyOf(caveats);
    }

    /**
     * @return The Macaroon location
     */
    public String getLocation() {
        return location;
    }

    /**
     * @return The Macaroon identifier
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * @return The matched serialization
     */
    public MacaroonSerialization getSerialization() {
        return serialization;
    }

    /**
     * @return Claims decoded from verified first-party caveats
     */
    public Map<String, Object> getClaims() {
        return claims;
    }

    /**
     * @return First-party caveats
     */
    public List<MacaroonCaveat> getCaveats() {
        return caveats;
    }
}
