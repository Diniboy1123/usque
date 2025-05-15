package config

import (
	"fmt"
	"reflect"

	"github.com/spf13/cobra"
)

// ReadFromCmd reads the configuration from command line flags.
func ReadFromCmd(config interface{}, cmd *cobra.Command) error {
	cmdAutoGet := func(cmd *cobra.Command, name string, typeName string) (interface{}, error) {
		switch typeName {
		case "string":
			return cmd.Flags().GetString(name)
		case "int":
			return cmd.Flags().GetInt(name)
		case "uint16":
			return cmd.Flags().GetUint16(name)
		case "bool":
			return cmd.Flags().GetBool(name)
		case "time.Duration":
			return cmd.Flags().GetDuration(name)
		case "[]string":
			return cmd.Flags().GetStringArray(name)
		default:
			return nil, fmt.Errorf("unsupported type %s", typeName)
		}
	}

	v := reflect.ValueOf(config)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("config must be a non-nil pointer")
	}

	var processStruct func(reflect.Value) error
	processStruct = func(v reflect.Value) error {
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.Kind() == reflect.Struct && t.Field(i).Anonymous {
				if err := processStruct(field); err != nil {
					return err
				}
				continue
			}

			tag := t.Field(i).Tag.Get("cmd")
			if tag == "" {
				continue
			}

			value, err := cmdAutoGet(cmd, tag, field.Type().String())
			if err != nil {
				return fmt.Errorf("failed to get flag %s: %v", tag, err)
			}

			field.Set(reflect.ValueOf(value))
		}
		return nil
	}

	return processStruct(v.Elem())
}
