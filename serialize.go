package kms

import (
	"fmt"
	"reflect"
	"sort"
)

func innerSerialize(txData map[string]interface{}, keys []string) (string, error) {
	var ret string

	for _, key := range keys {
		value := txData[key]

		if value == nil {
			ret += `\0`
			continue
		}

		vt := reflect.ValueOf(value)
		switch vt.Kind() {
		case reflect.String:
			fmt.Printf("%v:%v", key, value)
			return fmt.Sprintf("%v.%v", key, value), nil
		case reflect.Map:
			innerData := vt.Interface().(map[string]interface{})
			innerKeys := make([]string, 0, len(innerData))
			for k := range innerData {
				innerKeys = append(innerKeys, k)
			}
			return innerSerialize(innerData, innerKeys)
		case reflect.Array:
			var arrRet string
			arrayData := vt.Interface().([]string)
			for _, value := range arrayData {
				arrRet += value
				arrRet += "."
			}
			return arrRet, nil
		default:
			fmt.Printf("%v:%v", key, value)
			return "", fmt.Errorf("invaild type: %v", vt)
		}
	}

	return ret, nil
}

// TODO : not implemented
func Serialize(txData map[string]interface{}) string {
	sortedKeys := make([]string, 0, len(txData))
	for k := range txData {
		sortedKeys = append(sortedKeys, k)
	}

	sort.Strings(sortedKeys)

	innerSerialize(txData, sortedKeys)

	return ""
}
