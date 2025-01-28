package util

import "log"

func LogError(err error) {
	if err != nil {
		log.Println("ERROR:", err)
	}
}

func LogInfo(msg string) {
	log.Println("INFO:", msg)
}
