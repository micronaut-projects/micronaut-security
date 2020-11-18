package io.micronaut.security.oauth2.client.condition

import io.micronaut.context.ApplicationContext
import io.micronaut.context.BeanContext
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class ClientCredentialsEnabledSpec extends Specification {

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

            'micronaut.security.oauth2.clients.authserveropeniddisabled.openid.issuer'                             : issuer,
            'micronaut.security.oauth2.clients.authserveropeniddisabled.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.authserveropeniddisabled.client-secret'                             : clientScret,
            'micronaut.security.oauth2.clients.authserveropeniddisabled.enabled'                                   : false,

            'micronaut.security.oauth2.clients.authservermanualdisabled.token.auth-method'                         : "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanualdisabled.token.url'                                 : issuer,
            'micronaut.security.oauth2.clients.authservermanualdisabled.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.authservermanualdisabled.client-secret'                             : clientScret,
            'micronaut.security.oauth2.clients.authservermanualdisabled.client-credentials.enabled'                : false,

            'micronaut.security.oauth2.clients.authservermanual.token.auth-method'                         : "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanual.token.url'                                 : issuer,
            'micronaut.security.oauth2.clients.authservermanual.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.authservermanual.client-secret'                             : clientScret,

            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.issuer'    : issuer,
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.token.auth-method': "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.token.url'        : issuer,
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-id'        : clientId,
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-secret'    : clientScret,

            'micronaut.security.oauth2.clients.notokennoissuer.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.notokennoissuer.client-secret'                             : clientScret,

            'micronaut.security.oauth2.clients.openiddisabled.openid.issuer'                             : issuer,
            'micronaut.security.oauth2.clients.openiddisabled.client-id'                                 : clientId,
            'micronaut.security.oauth2.clients.openiddisabled.client-secret'                             : clientScret,
            'micronaut.security.oauth2.clients.openiddisabled.client-credentials.enabled'                : false,
    ])

    @Shared
    BeanContext beanContext = applicationContext.getBean(BeanContext)

    @Unroll
    void "test bean is enabled depending on configuration"() {
        expect:
        beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("authserveropenid")).isPresent()
        beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("authservermanual")).isPresent()
        beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("authservermanualtakesprecedenceoveropenid")).isPresent()
        !beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("notokennoissuer")).isPresent()
        !beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("openiddisabled")).isPresent()
        !beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("authservermanualdisabled")).isPresent()
        !beanContext.findBean(ClientCredentialsClient, Qualifiers.byName("authserveropeniddisabled")).isPresent()
    }

}
