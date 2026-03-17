# Design Notes — cpp-sbom-builder

---

## Section 1 — Detection Strategy

### Implemented detectors

| Detector | Signal source | Confidence |
|---|---|---|
| `VcpkgDetector` | `vcpkg.json` — structured JSON manifest | Highest |
| `ConanDetector` | `conanfile.txt` — INI-style manifest | High |
| `CMakeDetector` | `CMakeLists.txt`, `*.cmake` — `find_package()` calls | Medium |
| `IncludeScanner` | `#include` directives in `.cpp/.cc/.cxx/.h/.hpp/.hxx` | Lowest |

**vcpkg** and **Conan** are the most reliable sources because they are explicit, machine-generated package manifests with structured name and version fields. Versions declared there are authoritative.

**CMake** is a strong signal for which libraries the project *intends* to link, but version information depends on the developer having written `find_package(OpenSSL 1.1 REQUIRED)` rather than just `find_package(OpenSSL REQUIRED)`. Many real CMakeLists.txt files omit the version argument. The detector matches `find_package()` with a single-line regex; invocations split across multiple lines are not detected.

**IncludeScanner** is a best-effort fallback. It finds libraries that no manifest lists — e.g. a vendored header-only library checked directly into `include/` — but it cannot determine versions and produces a higher false-positive rate.

### Confidence hierarchy (merger)

When the same dependency is reported by multiple detectors with conflicting versions, the merger applies this priority order:

```
vcpkg (1) > conan (2) > cmake (3) > include (4)
```

If the highest-priority source reports `"unknown"` but a lower-priority source has a concrete version, the real version is used. This means a project that lists a package in vcpkg.json without a version field but *does* specify a version in CMakeLists.txt will still get a version in the output.

---

## Section 2 — False Positives & Inaccuracies

### How stdlib headers are filtered

`internal/stdlib` maintains a hardcoded `map[string]bool` covering:

- All C++ standard library headers (`vector`, `string`, `filesystem`, etc.)
- C standard headers (`stdio.h`, `stdint.h`, etc.)
- POSIX / system headers (`unistd.h`, `sys/socket.h`, `pthread.h`, etc.)

Before adding any `#include`-derived name to the results, `IncludeScanner` calls `stdlib.IsStdlib(header)` on the raw header path and again on the resolved dependency name. Both checks are necessary: the first catches path-style system headers like `sys/types.h`; the second catches bare names like `vector` that appear after `depNameFromHeader` strips the path prefix.

### How internal project headers are excluded

Two rules are applied in `scanFileIncludes`:

1. **Explicit relative paths** (`./foo.h`, `../bar.h`) are skipped unconditionally. These can only reference files within the same repository tree.
2. **Quoted includes with path separators** (`#include "internal/myheader.h"`) are skipped. The C++ convention is that angle-bracket includes (`<lib/header.h>`) refer to installed system or third-party libraries, while quoted includes with slashes refer to project-local files. Only quoted flat names (`#include "config.h"`) are considered, since some projects install single-file third-party headers directly.

### How CMake pseudo-packages are filtered

`CMakeDetector` maintains a package-level `map[string]bool` called `cmakePseudoPackages`. After extracting and lowercasing a `find_package()` name, `parseCMakeFile` checks the map and skips the entry if it matches. The filter currently covers:

- `threads` — resolves to pthreads or the Win32 threading API; has no external package identity
- `cmake`, `ctest`, `cpack` — CMake's own toolchain components
- `packagehandlestandardargs`, `findpackagehandlestandardargs` — CMake helper modules included by other Find-modules
- `cmakepackageconfighelpers` — CMake utility module for writing config files

The filter is a static allowlist and is not user-configurable. Because the CMake ecosystem has hundreds of helper modules beyond this set, less common built-in modules that are not yet listed will still produce false-positive SBOM components.

### Remaining sources of false positives

- **Vendored header-only libraries.** A project that copies `nlohmann/json.hpp` or `stb_image.h` directly into its source tree will produce a component entry. The tool has no way to distinguish a vendored copy from an installed external dependency purely from the `#include` directive.
- **Platform-specific SDK headers.** Windows SDK headers (`windows.h`, `winsock2.h`, `d3d11.h`) and macOS frameworks are not in the stdlib allowlist. Scanning a platform-specific codebase will produce false-positive components for these.
- **Non-evaluated CMake conditionals.** `find_package()` calls inside `if(FEATURE_X)` blocks are always extracted regardless of whether that feature flag would actually be enabled. A project with many optional dependencies will overcount.
- **Multi-line `find_package()` calls not detected.** The CMake detector matches `find_package()` with a single-line regex. Invocations split across multiple lines — a common style for long argument lists — are silently missed and produce no component entry.
- **Test-only dependencies.** The walker does not discriminate between production source and test directories. Google Test or Catch2, found only in `test/`, will appear as components alongside production dependencies.

---

## Section 3 — Version Detection

### Which detectors reliably detect versions

**vcpkg** and **Conan** are the only fully reliable version sources. Both formats have explicit, structured version fields:

- vcpkg: `{"name": "openssl", "version": "1.1.1"}` in `vcpkg.json`
- Conan: `openssl/1.1.1` as a positional format in `conanfile.txt`

**CMake** can detect versions when the developer writes `find_package(OpenSSL 1.1 REQUIRED)`. The version argument is optional in CMake syntax, so many real-world files omit it. When absent, the CMake detector sets `version = "unknown"`.

**IncludeScanner** never produces a version. An `#include` directive carries no version information by design.

### What happens when only an include is found

If a dependency is detected solely by `IncludeScanner` with no manifest confirmation, it is emitted with `version: "unknown"` and a purl of `pkg:generic/<name>`. This is an honest representation of what the tool knows: the library is present, but its version cannot be determined statically.

### How version detection could be improved

Several approaches would increase version coverage:

1. **Parse version-define headers.** Many libraries ship a `<name>/version.h` that defines `#define OPENSSL_VERSION_TEXT "1.1.1"`. A follow-up scanner could open the first discovered header file for a dependency and regex-search for `VERSION` defines.
2. **Parse `pkg-config` `.pc` files.** Implementing a pkgconfig detector would cover any library that ships a `.pc` file (most system libraries on Linux). This is not yet implemented; the priority slot previously reserved for it in the merger has been removed pending a full implementation.
3. **Read `vcpkg.lock` / `conan.lock`.** Lock files contain exact resolved versions including transitive dependencies. These are higher-confidence than the manifest files currently parsed.
4. **CMake `FetchContent` / `ExternalProject_Add`.** These directives often embed version strings as URL parameters or Git tags. Parsing them is non-trivial but would recover versions for projects that don't use a package manager.

---

## Section 4 — Performance at Scale

### Concurrent detector design

> **Interface change note:** The original proposal described a `Detect(ctx context.Context, root string)` signature, where each detector would receive a root path and walk the filesystem itself. The implemented interface is:
>
> ```go
> Detect(ctx context.Context, files []string) ([]Dependency, error)
> ```
>
> This change was made during implementation to introduce a single shared `filepath.WalkDir` pass in `cmd/root.go`. The resulting flat, skip-dir-pruned file slice is passed to every detector instead of each detector walking the tree independently. This eliminates redundant I/O — the filesystem is traversed exactly once regardless of how many detectors run.

All four detectors run in separate goroutines launched by `cmd.Run`. Rather than each detector walking the filesystem, `cmd/root.go` performs a single `filepath.WalkDir` pass and builds a flat, skip-dir-pruned `[]string` of absolute file paths. That slice is passed directly to each detector's `Detect` method. Each detector filters the list for the paths it cares about and reads those files; it never calls `filepath.WalkDir` itself. Results are sent into a buffered channel sized to the number of detectors so no goroutine ever blocks on send. A single closer goroutine calls `sync.WaitGroup.Wait()` then closes the channel, after which the main goroutine drains and merges results.

This design means detector wall-clock time equals the slowest single detector, not their sum — on a 4-core machine scanning a 50k-file project this is roughly a 4× speedup over sequential execution.

### Worker pool inside IncludeScanner

`IncludeScanner` has a second level of concurrency: a pool of `GOMAXPROCS` worker goroutines each pulling file paths from a closed, pre-filled channel. File I/O is the bottleneck for include scanning, and modern NVMe storage handles many concurrent reads efficiently. Each worker calls `scanFileIncludes`, which is a pure function with no shared mutable state. Results are sent back over a buffered channel and merged sequentially in the calling goroutine — no mutex on the merge map.

### Why regex/string scanning rather than AST parsing

For the problem scope (static heuristic detection, not build-system emulation) a full C++ AST parser would add significant complexity with limited return. The concrete trade-offs:

| | Regex/string scanning | Full AST parsing |
|---|---|---|
| Implementation time | Hours | Weeks (libclang bindings + CGo) |
| Build reproducibility | Pure Go, zero C deps | Requires clang headers at build time |
| Handles malformed code | Yes — line-by-line | Often fails without a full compile environment |
| Evaluates `#ifdef` | No | Only with compile flags |
| Finds all `find_package` | Yes (case-insensitive regex) | Yes |

The only material capability gap is conditional evaluation (`#ifdef`, CMake `if/else`). For an SBOM that aims for completeness over precision, false positives from un-evaluated conditionals are preferable to silently missing dependencies because a compile flag was not passed.

### What would change for a production 10 GB monorepo

At that scale several assumptions break:

1. **Memory.** The current implementation already performs a single shared `filepath.WalkDir` pass in `cmd/root.go`, so the directory tree is traversed only once. However, the resulting file path list is accumulated in RAM in full before any detector runs. A streaming walker that feeds detectors via a shared channel would keep memory flat regardless of tree size.
2. **Incremental scanning.** A monorepo rarely changes entirely between CI runs. A content-hash cache (e.g. keyed on `(path, mtime, size)`) could skip files unchanged since the last run, reducing scan time to near-zero on warm runs.
3. **AST parsing for high-value directories.** For the `src/` subtrees that change frequently, investing in clang-based AST parsing of `#include` chains would eliminate the false-positive classes described in Section 2. The regex scanner could be retained for third-party vendored directories where a compile environment is unavailable.
4. **Parallel manifest parsing.** With thousands of `CMakeLists.txt` files (common in large monorepos with many sub-projects), the CMake detector's sequential file processing would become a bottleneck. It should adopt the same GOMAXPROCS worker-pool pattern as `IncludeScanner`.