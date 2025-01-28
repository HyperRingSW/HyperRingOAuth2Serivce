package repository

import "errors"

var (
	ErrChallengeNotFound  = errors.New("challenge not found")
	ErrUserNotFound       = errors.New("user not found")
	ErrCredentialNotFound = errors.New("token not found")
)
