package util

import (
	"encoding/json"
	"log"
)

func LogError(err error) {
	if err != nil {
		data := map[string]string{
			"level":   "ERROR",
			"message": err.Error(),
		}
		if jsonData, jErr := json.Marshal(data); jErr == nil {
			log.Println(string(jsonData))
		} else {
			log.Println("ERROR:", err)
		}
	}
}

func LogInfo(msg string) {
	data := map[string]string{
		"level":   "INFO",
		"message": msg,
	}
	if jsonData, err := json.Marshal(data); err == nil {
		log.Println(string(jsonData))
	} else {
		log.Println("INFO:", msg)
	}
}
