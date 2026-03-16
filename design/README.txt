## Engineering Assumptions

---

### Input & Project Structure
- The tool is designed to scan C++ projects of any size, including large monorepos. Individual files are assumed to be of reasonable size (under 10MB); the 10GB scale challenge is about **file count, not file size**.
- The project has already been **built** before the tool is run. Build artifacts (`.so`, `.a`, `.dll`, `.lib`) may be present but source files and manifests are the primary signal sources.
- The directory structure follows common C++ conventions — source files under `src/`, headers under `include/`, and build configs at or near the project root.
- The tool treats **any file within the scanned directory tree as potentially part of the project**, unless it matches known vendor/build output path patterns (e.g., `build/`, `cmake-build-*/`).

---

### Performance
- The scanner processes files **concurrently** using a worker pool to handle large file counts efficiently within a single run.
- The same file or path may be referenced by multiple metadata sources (e.g., a library appearing in both `CMakeLists.txt` and `vcpkg.json`). The tool **deduplicates findings within a single run** — no cross-run caching is implemented.
- No time guarantee is made for extremely large repos, but the design is I/O-bound aware and avoids loading entire files into memory where possible.

---

### Persistence
- The tool is **stateless between runs**. Every invocation is a fresh scan with no caching, incremental state, or history.
- Output is written to a single JSON file in the working directory (or a path specified via flag). No database, no intermediate files.

---

### Scope Limitations
- Only **direct dependencies** are detected. Transitive dependency resolution (i.e., what your dependencies depend on) is out of scope.
- The **C++ Standard Library** (`<vector>`, `<string>`, `<iostream>`, etc.) and common POSIX/system headers (`<unistd.h>`, `<pthread.h>`, etc.) are treated as internal and excluded from output.
- **Vendored source code** (e.g., a `third_party/` folder containing copied source) is a known limitation — the tool may partially detect these but makes no guarantee of completeness for vendored deps.
- If a version cannot be determined from any available signal, it is reported as `"unknown"` in the output.
- The tool targets the following detection sources as its defined scope: CMake files, vcpkg manifests, Conan files, pkg-config `.pc` files, and `#include` directives in source files.

---

### Error Handling
- **Unreadable files or directories** (permission errors) are skipped with a warning logged to stderr. They do not abort the scan.
- **Malformed config files** (e.g., invalid JSON in `vcpkg.json`) are skipped per-file with a warning. The tool continues scanning remaining sources.
- If **no dependencies are detected**, the tool exits successfully and produces a valid but empty SBOM — this is a legitimate result, not an error.
- The tool exits with a **non-zero exit code** only on fatal errors: invalid CLI arguments, target directory not found, or output file write failure.
- No network calls are made. All analysis is local and offline. A missing network connection will never cause a failure.