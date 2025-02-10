package util

import (
	"encoding/json"
)

func UserInfoToJSON(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}
