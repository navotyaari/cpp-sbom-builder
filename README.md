# cpp-sbom-builder

A command-line tool that scans a C++ project directory and produces a
[CycloneDX 1.4](https://cyclonedx.org/specification/overview/) JSON Software Bill of Materials (SBOM).
It identifies third-party dependencies by parsing CMake build files, vcpkg and Conan manifests,
and `#include` directives in source files — with no build-system invocation required.

---

## Prerequisites

- **Go 1.22** or later (`go version` to check)

---

## Build

```bash
git clone <repo-url>
cd cpp-sbom-builder
go build -o cpp-sbom-builder .
```

This produces a single self-contained binary. The `metadata.tools[0].version` field in every generated SBOM
will be `"dev"` when built this way.

**To stamp a release version into the binary**, pass the version string via `-ldflags` at build time:

```bash
go build -ldflags "-X cpp-sbom-builder/internal/formatter.toolVersion=1.2.3" -o cpp-sbom-builder .
```

Replace `1.2.3` with the actual release tag. The injected value appears verbatim in the
`metadata.tools[0].version` field of every SBOM the binary produces.

---

## Run

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--dir` | yes | — | Path to the C++ project root to scan |
| `--output` | no | `sbom.json` | Path for the output JSON file |

### Against the included sample project

```bash
./cpp-sbom-builder --dir testdata/sample_project --output sbom.json
```

Expected output:

```
SBOM written to sbom.json
```

### Against your own project

```bash
./cpp-sbom-builder --dir /path/to/your/cpp/project --output /tmp/my-sbom.json
```

---

## Run the test suite

```bash
go test ./...
```

All unit tests and the end-to-end integration test run together.
To run only the integration test:

```bash
go test -run TestIntegration ./...
```

---

## Example output

A generated `sbom.json` looks like this (abbreviated):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2024-11-01T12:00:00Z",
    "tools": [
      { "vendor": "cpp-sbom-builder", "name": "cpp-sbom-builder", "version": "1.2.3" }
    ],
    "component": {
      "type": "application",
      "bom-ref": "sample_project-unknown",
      "name": "sample_project",
      "version": "unknown",
      "purl": ""
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "openssl-1.1",
      "name": "openssl",
      "version": "1.1",
      "purl": "pkg:generic/openssl@1.1",
      "evidence": {
        "occurrences": [
          { "location": "testdata/sample_project/CMakeLists.txt" },
          { "location": "testdata/sample_project/src/main.cpp" }
        ]
      }
    }
  ]
}
```

---

## Known limitations

- **No build-system execution.** Dependency resolution is purely static. Conditional CMake blocks (`if(WIN32) ... find_package(...)`) are not evaluated; all `find_package` calls are treated as active.
- **CMake pseudo-package filter is incomplete.** The CMake detector skips a known set of built-in module names (`Threads`, `CMakePackageConfigHelpers`, `PackageHandleStandardArgs`, and a few others) that have no external package identity. Less common CMake utility modules not in this list will still produce false-positive entries.
- **Multi-line `find_package()` calls not detected.** The CMake detector matches `find_package()` with a single-line regex. Invocations split across multiple lines — a common style for long argument lists — are silently missed.
- **Include scanner is low-confidence.** `#include` scanning cannot determine versions. Any header-only or single-file library that ships alongside the project source will produce a false-positive entry with `version: "unknown"`.
- **conanfile.py not supported.** Only the plain-text `conanfile.txt` format is parsed. Python-based Conan manifests (`conanfile.py`) are out of scope because they are arbitrary Python scripts — dependencies can be declared dynamically based on environment variables, platform checks, subprocess calls, or any other runtime condition. Even with a Python interpreter available, executing the script in a different environment than the actual build would produce an unreliable or incorrect dependency list. This is the same fundamental limitation as CMake's unevaluated conditionals, but worse: CMake conditionals are at least statically enumerable, whereas a Python script is not.
- **No transitive dependencies.** The tool detects only direct dependencies declared in manifests or `#include`d headers. Transitive (indirect) dependencies are not resolved.
- **Version is "unknown" for include-only hits.** When a dependency is only detected via `#include` and no manifest file names it, no version information is available.
- **Windows SDK headers not in allowlist.** The stdlib allowlist covers C++ stdlib, C headers, and POSIX. Windows-specific headers (`windows.h`, `winsock2.h`, etc.) are not yet in the allowlist and will appear as false-positive components on Windows projects.