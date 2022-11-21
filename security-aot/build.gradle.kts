plugins {
    id("io.micronaut.build.internal.aot-module")
}
micronautBuild {
    aot {
        version.set("2.0.0-SNAPSHOT")
    }
}
micronautBuild {
    binaryCompatibility {
        enabled.set(false)
    }
}
dependencies {
    compileOnly(platform(mn.micronaut.bom))
    implementation(projects.securityOauth2)
    implementation(projects.securityJwt)

    testImplementation(mn.spock) {
        exclude("org.codehaus.groovy", "groovy-all")
    }
    testImplementation(platform(mn.micronaut.bom))
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.securityOauth2)
}
