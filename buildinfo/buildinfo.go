package buildinfo

import (
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

var (
	buildInfo      *debug.BuildInfo
	buildInfoValid bool
	readBuildInfo  sync.Once

	version     string
	readVersion sync.Once

	// Injected with ldflags at build!
	tag string
)

const (
	// develPrefix is prefixed to developer versions of the application.
	develPrefix = "v0.0.0-devel"
)

// Version returns the semantic version of the build.
// Use golang.org/x/mod/semver to compare versions.
func Version() string {
	readVersion.Do(func() {
		revision, valid := revision()
		if valid {
			revision = "+" + revision[:7]
		}
		if tag == "" {
			// This occurs when the tag hasn't been injected,
			// like when using "go run".
			version = develPrefix + revision
			return
		}
		version = "v" + tag
		// The tag must be prefixed with "v" otherwise the
		// semver library will return an empty string.
		if semver.Build(version) == "" {
			version += revision
		}
	})
	return version
}

// Time returns when the Git revision was published.
func Time() (time.Time, bool) {
	value, valid := find("vcs.time")
	if !valid {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic("couldn't parse time: " + err.Error())
	}
	return parsed, true
}

// revision returns the Git hash of the build.
func revision() (string, bool) {
	return find("vcs.revision")
}

// find panics if a setting with the specific key was not
// found in the build info.
func find(key string) (string, bool) {
	readBuildInfo.Do(func() {
		buildInfo, buildInfoValid = debug.ReadBuildInfo()
	})
	if !buildInfoValid {
		panic("couldn't read build info")
	}
	for _, setting := range buildInfo.Settings {
		if setting.Key != key {
			continue
		}
		return setting.Value, true
	}
	return "", false
}
