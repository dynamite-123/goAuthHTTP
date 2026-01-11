package models

type User struct {
	Id       string `json:"id,omitempty" bson:"_id,omitempty"`
	Username string `json:"username,omitempty" bson:"username,omitempty"`
	Email    string `json:"email,omitempty" bson:"email,omitempty"`
	Password string `json:"password,omitempty" bson:"password,omitempty"`
	Role     string `json:"role,omitempty" bson:"role,omitempty"`
	GoogleId string `json:"google_id,omitempty" bson:"google_id,omitempty"`
	Picture  string `json:"picture,omitempty" bson:"picture,omitempty"`
}
