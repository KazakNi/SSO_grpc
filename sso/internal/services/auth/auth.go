package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/storage"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		log:          log,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

// Login checks if user with given credentials exists in the system and returns access token
//
// If user exists, but password is incorrect, returns error
// If user doesn't exist, returns error
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {

	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)
	log.Info("attempting to login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("usr not found", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error())},
			)

			return "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
		}
		a.log.Error("fail to get user", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error())},
		)

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", storage.ErrInvalidCredentials)

		return "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, storage.ErrInvalidCredentials)
	}

	log.Info("Login successful")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", storage.ErrInvalidCredentials)

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {

	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("password hash generation failed", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error())},
		)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error())},
			)

			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}
		log.Error("failed to save user", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error())},
		)

		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user has been registered")

	return id, nil
}

func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {

	const op = "auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.String("userID", strconv.Itoa(int(userID))),
	)

	log.Info("checking for admin rights")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)

	if err != nil {

		if errors.Is(err, storage.ErrInvalidAppID) {
			log.Warn("wrong app ID", slog.Attr{
				Key:   "error",
				Value: slog.StringValue(err.Error())},
			)

			return false, fmt.Errorf("%s: %w", op, storage.ErrInvalidAppID)
		}

		log.Error("error while checking for admin rights", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error())},
		)

		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
