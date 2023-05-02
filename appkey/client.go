// Copyright 2023 karalabe/go-bluesky authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package appkey checks ensure an offered Bluesky password is
// an application key and not a master password, as well as does some
// additional jwt and time based checks.
// This logic was extracted from https://github.com/karalabe/go-bluesky,
// which ultimately will likely be a much better package than this one.
// This is currently lightly tested end-to-end by https://github.com/thepudds/gomoderate.
package appkey

// TODO: confirm no objections from @karalabe

import (
	"errors"
	"fmt"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrLoginUnauthorized is returned from a login attempt if the credentials
	// are rejected by the server or the local client (master credentials).
	ErrLoginUnauthorized = errors.New("unauthorized")

	// ErrMasterCredentials is returned from a login attempt if the credentials
	// are valid on the Bluesky server, but they are the user's master password.
	// Since that is a security malpractice, this library forbids it.
	ErrMasterCredentials = errors.New("master credentials used")

	// ErrSessionExpired is returned from any API call if the underlying session
	// has expired and a new login from scratch is required.
	ErrSessionExpired = errors.New("session expired")
)

// Check ensures an offered Bluesky password is
// an application key and not a master password, as well as does some
// additional jwt and time based checks.
func Check(sess *atproto.ServerCreateSession_Output) error {
	token, _, err := jwt.NewParser().ParseUnverified(sess.AccessJwt, jwt.MapClaims{})
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("unexpected type for claims: %T", token.Claims)
	}
	if claims["scope"] != "com.atproto.appPass" {
		return fmt.Errorf("%w: %w", ErrLoginUnauthorized, ErrMasterCredentials)
	}

	// Retrieve the expirations for the current and refresh JWT tokens
	current, err := token.Claims.GetExpirationTime()
	if err != nil {
		return err
	}
	if time.Until(current.Time) < 0 {
		return fmt.Errorf("%w: refresh token was valid until %v", ErrSessionExpired, current.Time)
	}

	if token, _, err = jwt.NewParser().ParseUnverified(sess.RefreshJwt, jwt.MapClaims{}); err != nil {
		return err
	}

	// TODO: this is 'refresh'. From initial look, original in karalabe/go-bluesky was checking for error,
	// but was not immediately checking validity of the time itself.
	_, err = token.Claims.GetExpirationTime()
	if err != nil {
		return err
	}

	return nil
}
