package io.micronaut.security.password.tck.pbkdf2;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

@Suite
@SelectPackages("io.micronaut.security.password.tck")
@SuiteDisplayName("PBKDF2 reference PasswordEncoder TCK")
public class Pbkdf2PasswordEncoderSuite {
}
