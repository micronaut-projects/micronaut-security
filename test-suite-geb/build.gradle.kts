plugins {
    id("io.micronaut.build.internal.security-tests")
    groovy
    `java-library`
}

repositories {
    mavenCentral()
    maven {
        setUrl("https://s01.oss.sonatype.org/content/repositories/snapshots/")
    }
}

dependencies {
    testImplementation(mn.snakeyaml)
    testImplementation(mn.reactor)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteKeycloak)
    testImplementation(projects.testSuiteKeycloak16)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
    testImplementation(projects.micronautSecurityOauth2)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.micronautSecuritySession)
    testImplementation(libs.geb.spock)

    testImplementation(libs.testcontainers.selenium)
    testImplementation(libs.selenium.remote.driver)
    testImplementation(libs.selenium.api)
    testImplementation(mn.micronaut.inject.groovy)
    testImplementation(libs.selenium.support)
    testRuntimeOnly(libs.selenium.firefox.driver)
    testRuntimeOnly(mn.logback.classic)
    testImplementation(mn.micronaut.websocket)
    testImplementation(mn.micronaut.jackson.databind)

}

tasks.withType<Test> {
    useJUnitPlatform()
    systemProperty("geb.env", System.getProperty("geb.env") ?: "dockerFirefox")
    systemProperty("webdriver.gecko.driver", System.getProperty("webdriver.gecko.driver"))
}
