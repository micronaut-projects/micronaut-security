package io.micronaut.security.filters.reload

import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.RuntimeBeanDefinition
import io.micronaut.context.env.PropertySource
import io.micronaut.context.reload.ClassChangeEvent
import io.micronaut.context.reload.ReloadStrategy
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.http.HttpRequest
import io.micronaut.runtime.context.scope.refresh.ConfigurationRefresher
import io.micronaut.runtime.context.scope.refresh.RefreshResult
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.filters.AuthenticationFetcher
import io.micronaut.security.filters.SecurityFilter
import io.micronaut.security.rules.ConfigurationInterceptUrlMapRule
import io.micronaut.security.rules.IpPatternsRule
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import jakarta.inject.Singleton
import org.jspecify.annotations.Nullable
import org.reactivestreams.Publisher
import spock.lang.Specification

import java.util.function.Supplier

class SecurityReloadSpec extends Specification {

    private static final String RELOADER = 'io.micronaut.security.filters.DevelopmentSecurityReloader'

    void "in development mode a security rule registered at runtime recreates the filter, which then holds it"() {
        given:
        ApplicationContext context = devContext(true)
        SecurityFilter filter = context.getBean(SecurityFilter)
        ConfigurationInterceptUrlMapRule urlMapRule = context.getBean(ConfigurationInterceptUrlMapRule)

        expect: 'the reloader exists only in development mode'
        context.containsBean(reloader())
        !filter.securityRules.any { it instanceof RejectingRule }

        when:
        context.registerBeanDefinition(RuntimeBeanDefinition.builder(RejectingRule, (Supplier<RejectingRule>) { new RejectingRule() })
            .exposedTypes(SecurityRule, RejectingRule)
            .build())
        SecurityFilter recreated = context.getBean(SecurityFilter)

        then: 'the filter collects the rules again'
        !recreated.is(filter)
        recreated.securityRules.any { it instanceof RejectingRule }

        and: 'the rules themselves were not touched'
        context.getBean(ConfigurationInterceptUrlMapRule).is(urlMapRule)

        cleanup:
        context.close()
    }

    void "in development mode a change of the security configuration recreates the rules that read it, and the filter"() {
        given:
        ApplicationContext context = devContext(true)
        ConfigurationRefresher refresher = context.getBean(ConfigurationRefresher)
        SecurityFilter filter = context.getBean(SecurityFilter)
        ConfigurationInterceptUrlMapRule urlMapRule = context.getBean(ConfigurationInterceptUrlMapRule)
        IpPatternsRule ipRule = context.getBean(IpPatternsRule)

        expect:
        urlMapRule.patternList*.access == [['isAnonymous()']]
        ipRule.patternList*.pattern() == ['0.0.0.0']

        when:
        RefreshResult refresh = edit(context, refresher, [
            'micronaut.security.intercept-url-map[0].access[0]': 'isAuthenticated()',
            'micronaut.security.ip-patterns'                   : ['127.0.0.1']
        ])
        ConfigurationInterceptUrlMapRule recreatedUrlMapRule = context.getBean(ConfigurationInterceptUrlMapRule)
        IpPatternsRule recreatedIpRule = context.getBean(IpPatternsRule)
        SecurityFilter recreatedFilter = context.getBean(SecurityFilter)

        then: 'applied in place'
        !refresh.requiresRestart()
        !recreatedUrlMapRule.is(urlMapRule)
        recreatedUrlMapRule.patternList*.access == [['isAuthenticated()']]
        !recreatedIpRule.is(ipRule)
        recreatedIpRule.patternList*.pattern() == ['127.0.0.1']

        and: 'the filter holds the new rules'
        !recreatedFilter.is(filter)
        recreatedFilter.securityRules.any { it.is(recreatedUrlMapRule) }
        !recreatedFilter.securityRules.any { it.is(urlMapRule) }

        cleanup:
        context.close()
    }

    void "in development mode a change of the endpoints configuration recreates the sensitive endpoint rule"() {
        given:
        ApplicationContext context = devContext(true)
        ConfigurationRefresher refresher = context.getBean(ConfigurationRefresher)
        SensitiveEndpointRule rule = context.getBean(SensitiveEndpointRule)

        expect:
        healthSensitivity(rule) == [false] as Set

        when:
        RefreshResult refresh = edit(context, refresher, ['endpoints.health.sensitive': true])
        SensitiveEndpointRule recreated = context.getBean(SensitiveEndpointRule)

        then: 'the new rule checks the health endpoint as sensitive'
        !refresh.requiresRestart()
        !recreated.is(rule)
        healthSensitivity(recreated) == [true] as Set

        cleanup:
        context.close()
    }

    void "in development mode a reload that retires a classloader recreates the rules, the fetchers and the filter, and a restart does not"() {
        given:
        ApplicationContext context = devContext(true)
        SecurityFilter filter = context.getBean(SecurityFilter)
        ConfigurationInterceptUrlMapRule urlMapRule = context.getBean(ConfigurationInterceptUrlMapRule)
        EmptyFetcher fetcher = context.getBean(EmptyFetcher)

        when: 'the application restarts: the new context has new rules'
        context.publishEvent(classChange(ReloadStrategy.RESTART))

        then:
        context.getBean(SecurityFilter).is(filter)
        context.getBean(ConfigurationInterceptUrlMapRule).is(urlMapRule)
        context.getBean(EmptyFetcher).is(fetcher)

        when:
        context.publishEvent(classChange(ReloadStrategy.RELOAD))

        then:
        !context.getBean(SecurityFilter).is(filter)
        !context.getBean(ConfigurationInterceptUrlMapRule).is(urlMapRule)
        !context.getBean(EmptyFetcher).is(fetcher)
        !context.getBean(SecurityFilter).authenticationFetchers.any { it.is(fetcher) }

        cleanup:
        context.close()
    }

    void "in development mode a context that does not track bean dependencies keeps the rules and the filter, rather than replace them under the beans that received them"() {
        given:
        ApplicationContext context = devContext(false)
        ConfigurationRefresher refresher = context.getBean(ConfigurationRefresher)
        SecurityFilter filter = context.getBean(SecurityFilter)
        ConfigurationInterceptUrlMapRule urlMapRule = context.getBean(ConfigurationInterceptUrlMapRule)

        expect:
        context.containsBean(reloader())

        when:
        context.registerBeanDefinition(RuntimeBeanDefinition.builder(RejectingRule, (Supplier<RejectingRule>) { new RejectingRule() })
            .exposedTypes(SecurityRule, RejectingRule)
            .build())
        RefreshResult refresh = edit(context, refresher, ['micronaut.security.intercept-url-map[0].access[0]': 'isAuthenticated()'])
        context.publishEvent(classChange(ReloadStrategy.RELOAD))

        then: 'nothing is recreated: the change is read after a restart, which the reloader asks for'
        refresh.requiresRestart()
        context.getBean(SecurityFilter).is(filter)
        context.getBean(ConfigurationInterceptUrlMapRule).is(urlMapRule)

        cleanup:
        context.close()
    }

    void "outside development mode there is no reloader and the filter and rules are built once, as they always have been"() {
        given:
        ApplicationContext context = ApplicationContext.run(securityProperties())
        ConfigurationRefresher refresher = context.getBean(ConfigurationRefresher)
        SecurityFilter filter = context.getBean(SecurityFilter)
        ConfigurationInterceptUrlMapRule urlMapRule = context.getBean(ConfigurationInterceptUrlMapRule)

        expect:
        !context.containsBean(reloader())

        when:
        context.registerBeanDefinition(RuntimeBeanDefinition.builder(RejectingRule, (Supplier<RejectingRule>) { new RejectingRule() })
            .exposedTypes(SecurityRule, RejectingRule)
            .build())
        edit(context, refresher, ['micronaut.security.intercept-url-map[0].access[0]': 'isAuthenticated()'])
        context.publishEvent(classChange(ReloadStrategy.RELOAD))

        then:
        context.getBean(SecurityFilter).is(filter)
        context.getBean(ConfigurationInterceptUrlMapRule).is(urlMapRule)
        !filter.securityRules.any { it instanceof RejectingRule }
        urlMapRule.patternList*.access == [['isAnonymous()']]

        cleanup:
        context.close()
    }

    private static ApplicationContext devContext(boolean track) {
        return ApplicationContext.builder()
            .properties(securityProperties() + ['micronaut.dev.enabled': true])
            .trackBeanDependencies(track)
            .start()
    }

    private static Map<String, Object> securityProperties() {
        return [
            'spec.name'                                        : 'SecurityReloadSpec',
            'micronaut.security.intercept-url-map[0].pattern'  : '/reload/**',
            'micronaut.security.intercept-url-map[0].access[0]': 'isAnonymous()',
            'micronaut.security.ip-patterns'                   : ['0.0.0.0']
        ]
    }

    private static RefreshResult edit(ApplicationContext context, ConfigurationRefresher refresher, Map<String, Object> properties) {
        context.environment.addPropertySource(PropertySource.of('edit-' + System.nanoTime(), properties, Integer.MAX_VALUE))
        return refresher.refresh()
    }

    private static Set<Boolean> healthSensitivity(SensitiveEndpointRule rule) {
        return rule.endpointMethods.findAll { it.key.declaringType.simpleName == 'HealthEndpoint' }.values() as Set
    }

    private static Class<?> reloader() {
        return Class.forName(RELOADER)
    }

    private static ClassChangeEvent classChange(ReloadStrategy strategy) {
        return new ClassChangeEvent(SecurityReloadSpec, 1, [SecurityReloadSpec.classLoader] as Set, SecurityReloadSpec.classLoader, [], strategy)
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'SecurityReloadSpec')
    static class EmptyFetcher implements AuthenticationFetcher<HttpRequest<?>> {
        @Override
        Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
            return Publishers.empty()
        }
    }

    static class RejectingRule implements SecurityRule<HttpRequest<?>> {
        @Override
        Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable Authentication authentication) {
            return Publishers.just(SecurityRuleResult.REJECTED)
        }
    }
}
