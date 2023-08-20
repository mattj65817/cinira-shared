plugins {
    kotlin("jvm")
}

dependencies {
    //<editor-fold desc="Test implementation dependencies">
    testImplementation("org.assertj:assertj-core:${project.ext["assertj_version"]}")
    testImplementation("org.junit.jupiter:junit-jupiter-api:${project.ext["junit_jupiter_version"]}")
    //</editor-fold>

    //<editor-fold desc="Test runtime-only dependencies">
    testRuntimeOnly("ch.qos.logback:logback-classic:${project.ext["logback_version"]}")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:${project.ext["junit_jupiter_version"]}")
    //</editor-fold>
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    withJavadocJar()
    withSourcesJar()
}

kotlin {
    jvmToolchain {}
}

tasks.withType<Test> {
    useJUnitPlatform()
}
