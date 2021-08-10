package io.micronaut.security.oauth2.configuration

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import spock.lang.Specification

class OauthConfigurationSpec extends Specification {
    static final SPEC_NAME_PROPERTY = 'spec.name'

    void "OauthConfiguration binds id and secret"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
        ], Environment.TEST)

        when:
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration)

        then:
        noExceptionThrown()
        clientConfiguration.getName() == "foo"
        clientConfiguration.getClientId() == "XXXX"
        clientConfiguration.getClientSecret() == "YYYY"

        cleanup:
        context.close()
    }

    void "OauthConfiguration binds audience if present"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
                'micronaut.security.oauth2.clients.foo.audience': 'ZZZZ',
        ], Environment.TEST)

        when:
        OauthClientConfiguration clientConfiguration = context.getBean(OauthClientConfiguration)

        then:
        noExceptionThrown()
        clientConfiguration.getName() == "foo"
        clientConfiguration.getClientId() == "XXXX"
        clientConfiguration.getClientSecret() == "YYYY"
        clientConfiguration.getAudience() == "ZZZZ"

        cleanup:
        context.close()
    }

    void "OauthConfiguration is enabled by default"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.oauth2.clients.foo.client-id': 'XXXX',
                'micronaut.security.oauth2.clients.foo.client-secret': 'YYYY',
        ], Environment.TEST)

        when:
        context.getBean(OauthClientConfiguration)

        then:
        noExceptionThrown()

        cleanup:
        context.close()
    }

    void "test configuration binding"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                (SPEC_NAME_PROPERTY): getClass().simpleName,
                'micronaut.security.oauth2.callback-uri': '/a/b/{provider}',
                'micronaut.security.oauth2.login-uri': '/a/c/{provider}',
                'micronaut.security.oauth2.default-provider': 'foo',
                'micronaut.security.oauth2.openid.logout-uri': '/test/logout',
                'micronaut.security.oauth2.openid.end-session.redirect-uri': '/test/home',
                'micronaut.security.oauth2.openid.claims-validation.issuer': false,
                'micronaut.security.oauth2.openid.claims-validation.audience': false,
                'micronaut.security.oauth2.openid.claims-validation.authorized-party': false,
                'micronaut.security.oauth2.openid.additional-claims.jwt': true,
                'micronaut.security.oauth2.openid.additional-claims.access-token': true,
                'micronaut.security.oauth2.openid.additional-claims.refresh-token': true,
        ], Environment.TEST)

        when:
        OauthConfiguration config = context.getBean(OauthConfiguration)

        then:
        noExceptionThrown()
        config.isEnabled()
        config.getCallbackUri() == "/a/b/{provider}"
        config.getLoginUri() == "/a/c/{provider}"
        config.getDefaultProvider().get() == "foo"
        config.getOpenid().getLogoutUri() == "/test/logout"
        config.getOpenid().getEndSession().map({es -> es.getRedirectUri()}).get() == "/test/home"
        !config.getOpenid().getClaimsValidation().isIssuer()
        !config.getOpenid().getClaimsValidation().isAudience()
        !config.getOpenid().getClaimsValidation().isAuthorizedParty()
        config.getOpenid().getAdditionalClaims().isJwt()
        config.getOpenid().getAdditionalClaims().isAccessToken()
        config.getOpenid().getAdditionalClaims().isRefreshToken()
    }
}
