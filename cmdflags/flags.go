package cmdflags

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/pflag"
)

func StringFlag(val *string, name, env, defaultValue, usage string) {
	if envVal := os.Getenv(env); envVal != "" {
		defaultValue = envVal
	}

	pflag.StringVar(val, name, defaultValue, usage+" Env: "+env)
}

func BoolFlag(val *bool, name, env string, defaultValue bool, usage string) {
	if envVal := os.Getenv(env); envVal != "" {
		envValBool, err := strconv.ParseBool(envVal)
		if err != nil {
			log.Fatalf("Invalid value %q for %q: must be a bool: %+v", envVal, env, err)
		}

		defaultValue = envValBool
	}

	pflag.BoolVar(val, name, defaultValue, usage+" Env: "+env)
}

func IntFlag(val *int, name, env string, defaultValue int, usage string) {
	if envVal := os.Getenv(env); envVal != "" {
		envValInt, err := strconv.Atoi(envVal)
		if err != nil {
			log.Fatalf("Invalid value %q for %q: must be an int: %+v", envVal, env, err)
		}

		defaultValue = envValInt
	}

	pflag.IntVar(val, name, defaultValue, usage+" Env: "+env)
}

func Uint16Flag(val *uint16, name, env string, defaultValue uint16, usage string) {
	if envVal := os.Getenv(env); envVal != "" {
		envValUint, err := strconv.ParseUint(envVal, 10, 16)
		if err != nil || envValUint > 65535 {
			log.Fatalf("Invalid value %q for %q: must be a uint16: %+v", envVal, env, err)
		}

		defaultValue = uint16(envValUint)
	}

	pflag.Uint16Var(val, name, defaultValue, usage+" Env: "+env)
}
