package io.micronaut.security

import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.AuthenticationArgumentBinder
import io.micronaut.security.authentication.AuthenticationExceptionHandler
import io.micronaut.security.authentication.BasicAuthAuthenticationConfiguration
import io.micronaut.security.authentication.BasicAuthAuthenticationFetcher
import io.micronaut.security.authentication.DefaultAuthorizationExceptionHandler
import io.micronaut.security.authentication.PrincipalArgumentBinder
import io.micronaut.security.config.InterceptUrlMapConverter
import io.micronaut.security.config.SecurityConfigurationProperties
import io.micronaut.security.endpoints.LoginController
import io.micronaut.security.endpoints.LoginControllerConfigurationProperties
import io.micronaut.security.endpoints.LogoutController
import io.micronaut.security.endpoints.LogoutControllerConfigurationProperties
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.rules.ConfigurationInterceptUrlMapRule
import io.micronaut.security.rules.IpPatternsRule
import io.micronaut.security.rules.SecuredAnnotationRule
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.token.TokenAuthenticationFetcher
import io.micronaut.security.token.config.TokenConfigurationProperties
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagator
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagatorConfiguration
import io.micronaut.security.token.propagation.TokenPropagationConfigurationProperties
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter
import io.micronaut.security.token.propagation.TokenPropagator
import io.micronaut.security.utils.DefaultSecurityService
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

class SecurityDisabledSpec extends Specification {

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                 : SecurityDisabledSpec.simpleName,
            'micronaut.security.enabled': false,
    ], Environment.TEST)

    @Unroll("if micronaut.security.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        embeddedServer.applicationContext.getBean(clazz)

        then:
        def e = thrown(NoSuchBeanException)
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                SecurityFilter,
                AuthenticationArgumentBinder,
                AuthenticationExceptionHandler,
                Authenticator,
                PrincipalArgumentBinder,
                InterceptUrlMapConverter,
                SecurityConfigurationProperties,
                LoginController,
                LoginControllerConfigurationProperties,
                LogoutController,
                LogoutControllerConfigurationProperties,
                DefaultAuthorizationExceptionHandler,
                ConfigurationInterceptUrlMapRule,
                IpPatternsRule,
                SecuredAnnotationRule,
                SensitiveEndpointRule,
                BasicAuthAuthenticationFetcher,
                BasicAuthAuthenticationConfiguration,
                TokenConfigurationProperties,
                TokenPropagationConfigurationProperties,
                TokenPropagationHttpClientFilter,
                HttpHeaderTokenPropagator,
                HttpHeaderTokenPropagatorConfiguration,
                TokenAuthenticationFetcher,
                DefaultSecurityService,
        ]

        description = clazz.name
    }
}
