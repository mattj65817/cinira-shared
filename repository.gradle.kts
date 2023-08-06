/*
 * repository.gradle.kts
 *
 * Binds an `Action<RepositoryHandler>` as `ciniraArtifacts` on the extra properties of the enclosing scope. This is
 * used to define the internal artifact repository *once* and allow it to be included in multiple contexts, including
 * plugin repositories, dependency repositories, and publication targets.
 *
 * Use `apply(from = "./repository.gradle.kts")` from the scope which needs access to the repository, then apply the
 * repository as follows:
 *
 * ```
 * repositories {
 *     val ciniraArtifacts: Action<RepositoryHandler> by extra
 *     ciniraArtifacts(this)
 * }
 * ```
 *
 * This is less "concise" than I'd like it to be, but it's the only way I've found to express the repository
 * configuration once, in one file, and share it across all of the contexts where it may be needed. The primary problem
 * is that `pluginManagement { ... }` blocks are separate scripts which do not have access to functions or data defined
 * in their surrounding scripts, therefore it is not possible to share the repository configuration purely within
 * `settings.gradle.kts`, for example.
 *
 * This file should be present, copied and unmodified, in all projects that need access to the artifact repository.
 *
 */

/**
 * Environment variable which exposes the GitHub Personal Access Token in developer local environments.
 */
val PAT_ENV_KEY = "CINIRA_GITHUB_PERSONAL_ACCESS_TOKEN"

/**
 * Bind the repository handler to `extra` of the enclosing scope.
 */
extra.set("ciniraArtifacts", Action<RepositoryHandler> {
    maven {
        val cinira_artifacts_repo_username: String by extra("mattj65817")
        name = "ciniraArtifacts"
        url = uri("https://maven.pkg.github.com/mattj65817/cinira-artifacts")
        credentials {
            username = cinira_artifacts_repo_username
            password = if (extra.has("cinira_artifacts_repo_password")) {
                extra["cinira_artifacts_repo_password"] as String
            } else {
                System.getenv(PAT_ENV_KEY)
                    ?: throw GradleException("The [$PAT_ENV_KEY] environment variable has not been set.")
            }
        }
    }
})
