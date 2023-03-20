plugins {
    id("io.micronaut.build.internal.security-module")
    id("io.micronaut.build.internal.aot-module")
}

micronautBuild {
    aot {
        version.set("1.1.2")
    }
}

dependencies {
    implementation(projects.micronautSecurityOauth2)
    implementation(projects.micronautSecurityJwt)

    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.micronautSecurityOauth2)
    testImplementation(mnTest.micronaut.test.spock) {
        exclude("org.codehaus.groovy", "groovy-all")
    }
}
