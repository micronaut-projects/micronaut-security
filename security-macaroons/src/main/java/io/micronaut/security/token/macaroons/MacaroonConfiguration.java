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

import io.micronaut.core.util.Toggleable;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Configuration for Macaroon token generation and validation.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public interface MacaroonConfiguration extends Toggleable {

    /**
     * @return The root secret used to sign and verify Macaroons.
     */
    @Nullable
    String getSecret();

    /**
     * @return The location written into generated Macaroons.
     */
    String getLocation();

    /**
     * @return The identifier written into generated Macaroons.
     */
    String getIdentifier();

    /**
     * @return The serialization format used by generated Macaroons.
     */
    MacaroonSerialization getSerialization();

    /**
     * @return Serialization formats accepted by the validator.
     */
    List<MacaroonSerialization> getAcceptedSerializations();

    /**
     * @return Additional first-party caveats added to generated Macaroons.
     */
    List<String> getCaveats();

    /**
     * @return Whether the Macaroon {@link io.micronaut.security.token.generator.TokenGenerator} bean is enabled.
     */
    boolean isGeneratorEnabled();

    /**
     * @return Whether the Macaroon {@link io.micronaut.security.token.validator.TokenValidator} bean is enabled.
     */
    boolean isValidatorEnabled();
}
