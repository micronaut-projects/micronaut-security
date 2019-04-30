package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.authentication.UserDetails;

import javax.inject.Singleton;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Singleton
public class DefaultOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {

    @Override
    public UserDetails createUserDetails(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        Map<String, Object> claims = new HashMap<>(openIdClaims.getClaims());
        claims.put("oauthProvider", providerName);
        return new UserDetails(openIdClaims.getSubject(), Collections.emptyList(), claims);
    }

}
