package password

import (
	"errors"
	"net/mail"
	"path"
	"reflect"
	"time"

	"github.com/simonedbarber/go-template/html/template"

	"github.com/simonedbarber/auth"
	"github.com/simonedbarber/auth/auth_identity"
	"github.com/simonedbarber/auth/claims"
	"github.com/simonedbarber/mailer"
	"github.com/simonedbarber/qor/utils"
	"github.com/simonedbarber/session"
	"gorm.io/gorm"
)

var (
	// ConfirmationMailSubject confirmation mail's subject
	ConfirmationMailSubject = "Please confirm your account"

	// ConfirmedAccountFlashMessage confirmed your account message
	ConfirmedAccountFlashMessage = template.HTML("Confirmed your account!")

	// ConfirmFlashMessage confirm account flash message
	ConfirmFlashMessage = template.HTML("Please confirm your account")

	// ErrAlreadyConfirmed account already confirmed error
	ErrAlreadyConfirmed = errors.New("Your account already been confirmed")

	// ErrUnconfirmed unauthorized error
	ErrUnconfirmed = errors.New("You have to confirm your account before continuing")
)

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "confirm"

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			Subject: ConfirmationMailSubject,
		}, mailer.Template{
			Name:    "auth/confirmation",
			Data:    context,
			Request: context.Request,
			Writer:  context.Writer,
		}.Funcs(template.FuncMap{
			"current_user": func() interface{} {
				return currentUser
			},
			"confirm_url": func() string {
				confirmURL := utils.GetAbsURL(context.Request)
				confirmURL.Path = path.Join(context.Auth.AuthURL("password/confirm"))
				qry := confirmURL.Query()
				qry.Set("token", context.SessionStorer.SignedToken(claims))
				confirmURL.RawQuery = qry.Encode()
				return confirmURL.String()
			},
		}))
}

// DefaultConfirmHandler default confirm handler
var DefaultConfirmHandler = func(context *auth.Context) error {
	var (
		authInfo    auth_identity.Basic
		provider, _ = context.Provider.(*Provider)
		tx          = context.Auth.GetDB(context.Request)
		token       = context.Request.URL.Query().Get("token")
	)

	claims, err := context.SessionStorer.ValidateClaims(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			authInfo.Provider = provider.GetName()
			authInfo.UID = claims.Id
			authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()

			if err := tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).First(authIdentity).Error; errors.Is(err, gorm.ErrRecordNotFound) {
				err = auth.ErrInvalidAccount
			}

			if err == nil {
				if authInfo.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now
					if err = tx.Model(authIdentity).Updates(authInfo).Error; err == nil {
						context.SessionStorer.Flash(context.Writer, context.Request, session.Message{Message: ConfirmedAccountFlashMessage, Type: "success"})
						context.Auth.Redirector.Redirect(context.Writer, context.Request, "confirm")
						return nil
					}
				}
				err = ErrAlreadyConfirmed
			}
		}
	}

	return err
}
