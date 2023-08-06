plugins {
    base
}

apply(from = "./repository.gradle.kts")

subprojects {
    group = "cinira.shared"

    repositories {
        val ciniraArtifacts: Action<RepositoryHandler> by rootProject.extra
        mavenCentral()
        ciniraArtifacts(this)
    }
}

tasks.clean {
    delete("out")
}
