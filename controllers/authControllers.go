package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/tourism-auth/models"
	u "github.com/tourism-auth/utils"
)

var CreateAccount = func(w http.ResponseWriter, r *http.Request) {

	dataUser := &models.DataUser{}
	err := json.NewDecoder(r.Body).Decode(dataUser) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	resp := dataUser.Create() //Create account
	u.Respond(w, resp)
}

var Authenticate = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Accounts{}
	err := json.NewDecoder(r.Body).Decode(account) //decode the request body into struct and failed if any error occur
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	resp := models.Login(account.Username, account.Password)
	u.Respond(w, resp)
}
