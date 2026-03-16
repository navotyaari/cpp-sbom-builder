package stdlib_test

import (
	"testing"

	"cpp-sbom-builder/internal/stdlib"
)

func TestIsStdlib(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		// ── Required cases from the spec ─────────────────────────────────────
		{"vector", true},
		{"<string>", true},  // angle-bracket normalisation
		{"unistd.h", true},
		{"openssl/ssl.h", false},
		{"boost/regex.hpp", false},

		// ── C++ stdlib coverage ───────────────────────────────────────────────
		{"<iostream>", true},
		{"algorithm", true},
		{"memory", true},
		{"thread", true},
		{"mutex", true},
		{"chrono", true},
		{"functional", true},
		{"utility", true},
		{"tuple", true},
		{"array", true},
		{"deque", true},
		{"list", true},
		{"queue", true},
		{"stack", true},
		{"bitset", true},
		{"numeric", true},
		{"iterator", true},
		{"stdexcept", true},
		{"typeinfo", true},
		{"type_traits", true},
		{"optional", true},
		{"variant", true},
		{"any", true},
		{"filesystem", true},
		{"regex", true},
		{"random", true},
		{"fstream", true},
		{"sstream", true},
		{"istream", true},
		{"ostream", true},
		{"map", true},
		{"set", true},
		{"unordered_map", true},
		{"unordered_set", true},

		// ── C headers ────────────────────────────────────────────────────────
		{"stdio.h", true},
		{"stdlib.h", true},
		{"string.h", true},
		{"math.h", true},
		{"time.h", true},
		{"assert.h", true},
		{"errno.h", true},
		{"limits.h", true},
		{"float.h", true},
		{"ctype.h", true},
		{"stdint.h", true},
		{"stddef.h", true},
		{"stdbool.h", true},

		// ── POSIX headers ─────────────────────────────────────────────────────
		{"fcntl.h", true},
		{"sys/types.h", true},
		{"sys/stat.h", true},
		{"sys/socket.h", true},
		{"pthread.h", true},
		{"signal.h", true},
		{"dirent.h", true},
		{"dlfcn.h", true},
		{"netinet/in.h", true},
		{"arpa/inet.h", true},

		// ── Third-party / unknown — must return false ─────────────────────────
		{"boost/filesystem.hpp", false},
		{"nlohmann/json.hpp", false},
		{"gtest/gtest.h", false},
		{"curl/curl.h", false},
		{"zlib.h", false},
		{"openssl/evp.h", false},
		{"fmt/format.h", false},
		{"spdlog/spdlog.h", false},
		{"", false},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.header, func(t *testing.T) {
			got := stdlib.IsStdlib(tc.header)
			if got != tc.want {
				t.Errorf("IsStdlib(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

// TestIsStdlib_AngleBracketVariants confirms normalisation works for all
// bracket combinations so that scanner output is accepted regardless of format.
func TestIsStdlib_AngleBracketVariants(t *testing.T) {
	variants := []string{"vector", "<vector>"}
	for _, v := range variants {
		if !stdlib.IsStdlib(v) {
			t.Errorf("IsStdlib(%q) = false, want true", v)
		}
	}
}
