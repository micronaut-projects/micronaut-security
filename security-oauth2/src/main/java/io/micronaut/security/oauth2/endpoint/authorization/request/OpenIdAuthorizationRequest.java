package io.micronaut.security.oauth2.endpoint.authorization.request;

import javax.annotation.Nullable;
import java.util.List;

public interface OpenIdAuthorizationRequest extends AuthorizationRequest {

    String PARAMETER_RESPONSE_MODE = "response_mode";
    String PARAMETER_NONCE = "nonce";
    String PARAMETER_DISPLAY = "display";
    String PARAMETER_PROMPT = "prompt";
    String PARAMETER_MAX_AGE = "max_age";
    String PARAMETER_UI_LOCALES = "ui_locales";
    String PARAMETER_ID_TOKEN_HINT = "id_token_hint";
    String PARAMETER_LOGIN_HINT = "login_hint";
    String PARAMETER_ACR_VALUES = "acr_values";

    /**
     *
     * @return String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     */
    @Nullable
    String getNonce();

    /**
     *
     * @return Hint to the Authorization Server about the login identifier the End-User might use to log in.
     */
    @Nullable
    String getLoginHint();

    /**
     *
     * @return Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise, it SHOULD return an error, such as login_required.
     */
    @Nullable
    String getIdTokenHint();


    /**
     *
     * @return Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.
     */
    @Nullable
    String getResponseMode();

    /**
     *
     * @return ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
     */
    @Nullable
    Display getDisplay();

    /**
     *
     * @return Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
     */
    @Nullable
    Prompt getPrompt();

    /**
     *
     * @return Maximum Authentication Age.
     */
    @Nullable
    Integer getMaxAge();

    /**
     *
     * @return End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
     */
    @Nullable
    List<String> getUiLocales();

    /**
     *
     * @return Requested Authentication Context Class Reference values.
     */
    @Nullable
    List<String> getAcrValues();
}
