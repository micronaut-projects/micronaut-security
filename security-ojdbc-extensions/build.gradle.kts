import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.1.0")
    testFramework = TestFramework.JUNIT6
}
