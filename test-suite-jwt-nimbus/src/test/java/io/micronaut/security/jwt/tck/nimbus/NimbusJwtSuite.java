package io.micronaut.security.jwt.tck.nimbus;

import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.SuiteDisplayName;

@Suite
@SelectPackages("io.micronaut.security.jwt.tck")
@SuiteDisplayName("Nimbus JWT TCK")
public class NimbusJwtSuite {
}
