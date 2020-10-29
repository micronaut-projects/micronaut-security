package io.micronaut.security.oauth2.client.condition

import io.micronaut.context.ApplicationContext
import io.micronaut.context.BeanContext
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class OauthClientTokenManuallyConfiguredConditionSpec extends Specification {
    @Shared
    String clientScret = '1lk7on551mctn5gc78d1742at53l3npo3m375q0hcvr9t3eehgcf'

    @Shared
    String clientId = '3ljrgej68ggm7i720o9u12t7lm'

    @Shared
    String issuer = "http://foo.bar"

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = ApplicationContext.run([
            'micronaut.security.oauth2.clients.authserveropenid.openid.issuer'                             : issuer,
            'micronaut.security.oauth2.clients.authserveropenid.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.authserveropenid.client-secret'                             : clientScret,

            'micronaut.security.oauth2.clients.authservermanual.token.auth-method'                         : "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanual.token.url'                                 : issuer,
            'micronaut.security.oauth2.clients.authservermanual.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.authservermanual.client-secret'                             : clientScret,

            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.issuer'    : issuer,
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.token.auth-method': "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.token.url'        : issuer,
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-id'        : clientId,
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-secret'    : clientScret,

            'micronaut.security.oauth2.clients.notokennoissuer.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.notokennoissuer.client-secret'                             : clientScret,

    ])

    @Shared
    BeanContext beanContext = applicationContext.getBean(BeanContext)

    @Unroll
    void "#description"(boolean expected, String name) {
        expect:
        expected == !OauthClientTokenManuallyConfiguredCondition.tokenEndpointIsManuallyConfigured(beanContext, name).isPresent()

        where:
        expected || name
        false    || 'authserveropenid'
        true     || 'authservermanual'
        true     || 'authservermanualtakesprecedenceoveropenid'
        false    || 'notokennoissuer'
        description = createDescription(name, OpenIdIssuerTokenNotManuallyConfiguredCondition, expected)
    }

    String createDescription(String name, Class clazz, boolean expected) {
        if (name == 'authserveropenid') {
            return "if openid.issuer is set and no token endpoint is manually configured ${clazz.simpleName} returns $expected"
        }
        if (name == 'authservermanual') {
            return "if openid.issuer is not set and token endpoint is manually configured ${clazz.simpleName} returns $expected"
        }
        if (name == 'authservermanualtakesprecedenceoveropenid') {
            return "if openid.issuer is set and token endpoint is manually configured ${clazz.simpleName} returns $expected"
        }
        if (name == 'notokennoissuer') {
            return "if openid.issuer is not set and neither token is manually configured ${clazz.simpleName} returns $expected"
        }
    }
}
