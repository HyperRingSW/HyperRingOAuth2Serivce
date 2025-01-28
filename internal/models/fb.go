package models

type FBResponse struct {
	Id      string    `json:"id"`
	Name    string    `json:"name"`
	Email   string    `json:"email"`
	Picture fbPicture `json:"picture"`
}

type fbPicture struct {
	Data fbPictureData `json:"data"`
}

type fbPictureData struct {
	Height       int    `json:"height"`
	IsSilhouette bool   `json:"is_silhouette"`
	Url          string `json:"url"`
	Width        int    `json:"width"`
}
