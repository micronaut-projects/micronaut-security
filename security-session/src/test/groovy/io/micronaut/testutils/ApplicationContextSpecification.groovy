package io.micronaut.testutils

import io.micronaut.context.ApplicationContext
import spock.lang.Shared
import spock.lang.Specification

abstract class ApplicationContextSpecification extends Specification implements ConfigurationFixture {

    @Shared
    ApplicationContext applicationContext = ApplicationContext.run(configuration)
}
