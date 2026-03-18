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

### Against a real-world project

[Crow](https://github.com/CrowCpp/Crow) is a small, well-known open source C++ web framework that has both a
`vcpkg.json` and a `CMakeLists.txt` with `find_package()` calls. Scanning it exercises the vcpkg detector,
the CMake detector, and the include scanner simultaneously, and the merger's deduplication is visible in the
output because the same dependencies appear across multiple manifest and source files.

Crow is not included in this repository. Clone it yourself, then run the tool against it:

```bash
git clone https://github.com/CrowCpp/Crow.git --depth=1
./cpp-sbom-builder --dir Crow --output crow-sbom.json
```

Expected output:

```
SBOM written to crow-sbom.json
```

#### What to verify

Open `crow-sbom.json` and check the following.

**Top-level envelope fields** — the document should open with:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
```

**Known dependencies from `vcpkg.json`** — Crow's manifest declares three direct dependencies.
All three must appear as components:

| Name | Expected in vcpkg.json | Expected in CMakeLists.txt |
|------|------------------------|----------------------------|
| `asio` | ✓ | ✓ (`find_package(asio)`) |
| `openssl` | ✓ | ✓ (`find_package(OpenSSL)`, inside `CROW_ENABLE_SSL` block) |
| `zlib` | ✓ | ✓ (`find_package(ZLIB)`, inside `CROW_ENABLE_COMPRESSION` block) |

**Merger deduplication is working** — `asio`, `openssl`, and `zlib` each appear in both `vcpkg.json`
and `CMakeLists.txt`. For each of those components, the `sources` array in the SBOM should contain
more than one detector name (e.g. `["vcpkg", "cmake"]`), and the `occurrences` list in `evidence`
should include paths to both files. If any of these components shows only a single source, the merger
is not combining results correctly.

**No stdlib false positives** — scan the component names and confirm that none of the following
appear: `vector`, `string`, `iostream`, `algorithm`, `map`, `memory`. These are C++ standard library
headers and must be filtered out by the include scanner.

**No CMake pseudo-package false positives** — confirm that `threads`, `cmake`, `ctest`, and
`packagehandlestandardargs` do not appear as components. These are CMake-internal module names
that the CMake detector is required to suppress.

**Component count is in a reasonable range** — a default-options `--depth=1` clone of Crow
should produce approximately 5–8 components in total. The exact number depends on which
third-party headers the include scanner resolves from Crow's `include/crow/` directory.
A count significantly outside that range (for example, 0 or 50+) indicates a problem worth
investigating.

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