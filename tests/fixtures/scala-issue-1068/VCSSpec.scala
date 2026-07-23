package svsimTests

class VCSSpec extends BackendSpec {
  val backend =
    try {
    }

  backend match {
    case Right(backend) =>
      describe("VCS coverage options") {
        they("coverage options should produce a coverage database") {
          simulation.run(
          ) { _ => }
          workspace.generateAdditionalSources(None)
          val simulation = workspace.compile(
            backendSpecificSettings = compilationSettings.copy(
              coverageSettings = vcs.Backend.CoverageSettings(
                portsonly = true,
                ignoreMissingDefault = true
              )
            ),
            customSimulationWorkingDirectory = None,
            verbose = false
          )
        }

        they("debug access options should produce correct flag format with mixed plus and standalone flags") {
          import vcs.Backend.CompilationSettings._
          workspace.elaborateGCD()
          workspace.generateAdditionalSources(None)
          val simulation = workspace.compile(
          )(
            workingDirectoryTag = "vcs",
            commonSettings = CommonCompilationSettings(),
            backendSpecificSettings = compilationSettings.copy(
              traceSettings = TraceSettings(
                fsdbSettings = Some(
                  TraceSettings.FsdbSettings(
                    sys.env.getOrElse(
                      "VERDI_HOME",
                      throw new RuntimeException("VERDI_HOME was not set")
                    )
                  )
                )
              )
            ),
          ) { _ => }
          Paths.get(workspace.absolutePath, "workdir-vcs", "trace.fsdb").toFile must (exist)
        }
      }
  }

  def after(): Int = 1
}

class FollowingSpec
