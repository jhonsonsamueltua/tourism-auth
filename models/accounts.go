package models

import (
	"os"
	"strings"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"

	u "github.com/tourism-auth/utils"
)

/*
JWT claims struct
*/
type Token struct {
	UserId uint
	jwt.StandardClaims
}

//a struct to rep user account
type Accounts struct {
	gorm.Model
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Token    string `json:"token";sql:"-"`
}

//a struct to rep user profile
type Profile struct {
	gorm.Model
	AccountID   uint
	Name        string `json:"name"`
	Email       string `json:"email"`
	NoHP        string `json:"nohp"`
	Alamat      string `json:"alamat"`
	DOB         string `json:"dob"`
	SocialMedia string `json:"social_media"`
}

type DataUser struct {
	Account Accounts `json:"account"`
	Profile Profile  `json:"profile"`
}

type AuthResponse struct {
	Token    string
	Username string
	Role     string
}

//Validate incoming user details...
func (dataUser *DataUser) Validate() (map[string]interface{}, bool) {
	if len(dataUser.Account.Username) < 6 {
		return u.Message(false, "Username must contains minimal 6 characters"), false
	}

	if len(dataUser.Account.Password) < 8 {
		return u.Message(false, "Password must contains minimal 8 characters"), false
	}

	valPass := isValidPassword(dataUser.Account.Password)
	if !valPass {
		return u.Message(false, "Password must contains at least 7 letters, 1 number, 1 uppercase, 1 special character."), false
	}

	if !strings.Contains(dataUser.Profile.Email, "@") {
		return u.Message(false, "Email address is required"), false
	}

	//Username & Password must be unique
	tempAcc := &Accounts{}

	//check for errors and duplicate username and password
	err := GetDB().Table("accounts").Where("username = ? or password = ?", dataUser.Account.Username, dataUser.Account.Password).First(tempAcc).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return u.Message(false, "Connection error. Please retry"), false
	}
	if tempAcc.Username != "" || tempAcc.Password != "" {
		return u.Message(false, "Username or Password already use by another user."), false
	}

	//Email & No HP must be unique
	temp := &Profile{}

	//check for errors and duplicate emails
	err = GetDB().Table("profiles").Where("email = ?", dataUser.Profile.Email).First(temp).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return u.Message(false, "Connection error. Please retry"), false
	}
	if temp.Email != "" {
		return u.Message(false, "Email address already in use by another user."), false
	}

	//check for errors and duplicate no hp
	err = GetDB().Table("profiles").Where("no_hp = ?", dataUser.Profile.NoHP).First(temp).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return u.Message(false, "Connection error. Please retry"), false
	}
	if temp.NoHP != "" {
		return u.Message(false, "No HP address already in use by another user."), false
	}

	return u.Message(false, "Requirement passed"), true
}

func (dataUser *DataUser) Create() map[string]interface{} {
	if resp, ok := dataUser.Validate(); !ok {
		return resp
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(dataUser.Account.Password), bcrypt.DefaultCost)
	dataUser.Account.Password = string(hashedPassword)

	GetDB().Create(&dataUser.Account)

	if dataUser.Account.ID <= 0 {
		return u.Message(false, "Failed to create account, connection error.")
	}

	dataUser.Profile.AccountID = dataUser.Account.ID

	GetDB().Create(&dataUser.Profile)

	//Create new JWT token for the newly registered account
	tk := &Token{UserId: dataUser.Account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))

	respAuth := AuthResponse{tokenString, dataUser.Account.Username, dataUser.Account.Role}

	response := u.Message(true, "Account has been created")
	response["auth"] = respAuth
	return response
}

func Login(username, password string) map[string]interface{} {

	account := &Accounts{}
	err := GetDB().Table("accounts").Where("username = ?", username).First(account).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return u.Message(false, "Username address not found")
		}
		return u.Message(false, "Connection error. Please retry")
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		return u.Message(false, "Invalid login credentials. Please try again")
	}
	//Worked! Logged In
	account.Password = ""

	//Create JWT token
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString //Store the token in the response

	respAuth := AuthResponse{tokenString, account.Username, account.Role}
	resp := u.Message(true, "Logged In")
	resp["auth"] = respAuth
	return resp
}

func GetUsers(u uint) *Accounts {

	acc := &Accounts{}
	GetDB().Table("accounts").Where("sid = ?", u).First(acc)
	if acc.Username == "" { //User not found!
		return nil
	}

	acc.Password = ""
	return acc
}

func isValidPassword(s string) bool {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(s) >= 7 {
		hasMinLen = true
	}
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}
