package io.micronaut.security.oauth2

import io.micronaut.context.ApplicationContext
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

abstract class ApplicationContextSpecification extends Specification implements ConfigurationFixture {

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = ApplicationContext.run(configuration)
}
