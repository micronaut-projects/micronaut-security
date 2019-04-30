package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.authorization.request.Display;
import io.micronaut.security.oauth2.endpoint.authorization.request.Prompt;
import io.micronaut.security.oauth2.endpoint.authorization.request.ResponseType;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Optional;


public interface AuthorizationEndpointConfiguration extends EndpointConfiguration {

    Optional<String> getResponseMode();

    @Nonnull
    ResponseType getResponseType();

    /**
     *
     * @return ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
     */
    Optional<Display> getDisplay();

    /**
     *
     * @return Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
     */
    Optional<Prompt> getPrompt();

    /**
     *
     * @return Maximum Authentication Age.
     */
    Optional<Integer> getMaxAge();

    /**
     *
     * @return End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
     */
    Optional<List<String>> getUiLocales();

    /**
     *
     * @return Requested Authentication Context Class Reference values.
     */
    Optional<List<String>> getAcrValues();
}
