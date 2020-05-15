package io.micronaut.security

import io.micronaut.context.ApplicationContext
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

abstract class ApplicationContextSpecification extends Specification implements ConfigurationFixture {
    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run(configuration)
}
