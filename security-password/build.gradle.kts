import io.micronaut.build.TestFramework
plugins {
    id("io.micronaut.build.internal.security-full-coverage")
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
