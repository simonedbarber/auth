package password

import (
	"encoding/json"
	"log"
	"reflect"
	"strings"

	"errors"
	"github.com/jinzhu/copier"
	"github.com/simonedbarber/auth"
	"github.com/simonedbarber/auth/auth_identity"
	"github.com/simonedbarber/auth/claims"
	"github.com/simonedbarber/qor/utils"
	"github.com/simonedbarber/session"
	"gorm.io/gorm"
)

type Login struct {
	Login    string
	Password string
}

// DefaultAuthorizeHandler default authorize handler
var DefaultAuthorizeHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		authInfo    auth_identity.Basic
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
		login       Login
	)

	authInfo.Provider = provider.GetName()

	if req.Header.Get("Content-Type") == "application/json" {
		dec := json.NewDecoder(req.Body)
		err := dec.Decode(&login)

		if err != nil {
			return nil, auth.ErrInvalidRequest
		}

		authInfo.UID = login.Login
	} else {
		req.ParseForm()
		authInfo.UID = strings.TrimSpace(req.Form.Get("login"))
	}

	if err := tx.Model(context.Auth.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, auth.ErrInvalidAccount
	}

	if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
		currentUser, _ := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)
		provider.Config.ConfirmMailer(authInfo.UID, context, authInfo.ToClaims(), currentUser)

		return nil, ErrUnconfirmed
	}
	if req.Header.Get("Content-type") == "application/json" {
		if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(login.Password)); err == nil {
			return authInfo.ToClaims(), err
		}
	} else {
		if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, strings.TrimSpace(req.Form.Get("password"))); err == nil {
			return authInfo.ToClaims(), err
		}
	}

	return nil, auth.ErrInvalidPassword
}

// DefaultRegisterHandler default register handler
var DefaultRegisterHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		err         error
		currentUser interface{}
		schema      auth.Schema
		authInfo    auth_identity.Basic
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*Provider)
	)

	req.ParseForm()
	if req.Form.Get("login") == "" {
		return nil, auth.ErrInvalidAccount
	}

	if req.Form.Get("password") == "" {
		return nil, auth.ErrInvalidPassword
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if err := tx.Model(context.Auth.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, auth.ErrInvalidAccount
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(strings.TrimSpace(req.Form.Get("password"))); err == nil {
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		schema.Email = authInfo.UID
		schema.RawInfo = req

		currentUser, authInfo.UserID, err = context.Auth.UserStorer.Save(&schema, context)
		if err != nil {
			return nil, err
		}

		// create auth identity
		authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		copier.Copy(authIdentity, authInfo)
		log.Printf("AuthIdentity: %v", authIdentity)
		log.Printf("AuthInfo: %v", authInfo)

		if err = tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).FirstOrCreate(authIdentity).Error; err == nil {
			if provider.Config.Confirmable {
				context.SessionStorer.Flash(context.Writer, req, session.Message{Message: ConfirmFlashMessage, Type: "success"})
				err = provider.Config.ConfirmMailer(schema.Email, context, authInfo.ToClaims(), currentUser)
			}

			return authInfo.ToClaims(), err
		}
	}

	return nil, err
}
