package io.micronaut.security.password.argon2;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

@Suite
@SelectPackages("io.micronaut.security.password.tck")
@SuiteDisplayName("Argon2 PasswordEncoder TCK")
public class Argon2PasswordEncoderSuite {
}
