/*
Package justClaims provides an API for extraordinarily simple access of token claims in a cookie. It wraps https://www.github.com/dgrijalva/jwt-go and returns/takes a go Map. It assumes one token, one cookie, but you can instantiate it multiple times. It, like other just* packages, is instantiated/configured through a structure to define its behavior. Simplicity does not generally come at the cost of performance, but we will be dropping hashmaps down the road.

See https://github.com/autopogo/GoServerSkeleton for a basic usage
*/
package justClaims

import (
    "net/http"
    "time"
		"errors"
    "gopkg.in/dgrijalva/jwt-go.v3"
    log "github.com/autopogo/justLogging"
)

// Config is a configuration structure to set constants needed when the server is live.
type ClaimsConfig struct { // BUG: Name Config is prone to conflicts
    Jwt_key string // Jwt_key defines the JWT Signing Hash Key
		Cookie_name string // Cookie_name defines the name of the cookie to store it in
		Cookie_persistent bool // If this is set to false, no expiry is set, which means it expires on window close (a UX hint)
		Cookie_https bool // Cookie fails except over HTTPS
		Cookie_server_only bool // Cookie not accessible to client (prevents XSS in modern browsers)
		MandatoryTokenRefresh bool // The token/cookie will be autorefresh on read
		MandatoryTokenRefreshThreshold float32  // Autorefresh will only occur if it is < this * LifeSpanNano
		LifeSpan int64 // Seconds jwt+cookie have alive (if cookie persistent)
}

var (
 ErrInternal = errors.New("justClaims: internal error")
 ErrBadClaim = errors.New("justClaims: bad claims")
)

// GetClaims reads and returns claims.
// It returns empty claims if there is no cookie or if they were invalid.
// It will refresh them according to MandatoryTokenRefresh*.
func (jCC *ClaimsConfig) GetClaims(w http.ResponseWriter, r *http.Request) (claims jwt.MapClaims, err error) {
	var t *jwt.Token

	// Grabbing cookie
	if cookie, err := r.Cookie(jCC.Cookie_name); err != nil {
		if (err == http.ErrNoCookie) {
			log.Enterf("justClaims GetClaims: No Cookie, returning empty map: %v", err);
			return make(map[string]interface{}), nil
		}
		log.Errorf("justClaims GetClaims: Weird error trying to find cookie: %v", err);
		return make(map[string]interface{}), ErrInternal
	} else {
		log.Enterf("justClaims GetClaims: Received Token: %v", cookie.Value)
		if t, err = jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return []byte(jCC.Jwt_key), nil
		}); err != nil {
			log.Errorf("justClaims GetClaims: Weird error parsing the JWT: %v", err);
			return make(map[string]interface{}), ErrInternal
		}
	}


	if t.Valid {
		claims = t.Claims.(jwt.MapClaims) // is this assertion necessary? it's default in the Parse()
		if _, ok := claims["exp"]; ok && jCC.MandatoryTokenRefresh {
			//TODO if exp < MandatoryTokenRefreshThreshold time (chang _ to val)
			log.Enterf("justCLiams GetClaims: Setting claims due to threshhold")
			jCC.SetClaims(w, r, claims)
			err = nil
		}
	} else {
		claims = make(map[string]interface{})
		err = ErrBadClaim
	}
	return
}

// SetClaims will sign and set the claims based on defaults set in Config.
func (jCC *ClaimsConfig) SetClaims(w http.ResponseWriter, r *http.Request, claims jwt.MapClaims) (err error) {
	cookie := &http.Cookie{ Name: jCC.Cookie_name,
		Secure: jCC.Cookie_https,
		HttpOnly: jCC.Cookie_server_only }
	jCC.updateExpiries(cookie, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if ss, err := token.SignedString([]byte(jCC.Jwt_key)); err != nil {
		log.Errorf("justClaims SetClaims: Couldn't sign the encrypted string: %v", err)
		return ErrBadClaim
	} else {
		cookie.Value = ss;
		log.Enterf("justClaims SetClaims: Setting: %v", ss)
		http.SetCookie(w, cookie)
	}
	return
}


// updateExperies just handles writing time values to the cookie and JWT.
func (jCC *ClaimsConfig) updateExpiries(cookie *http.Cookie, claims jwt.MapClaims) {
	if (jCC.Cookie_persistent) {
		cookie.Expires = time.Now().Add(time.Duration(jCC.LifeSpan * int64(time.Second)))
		log.Enterf("Time exp: %v", time.Now().Add(time.Duration(jCC.LifeSpan*1e9)))
		cookie.MaxAge = 0
	} else {
		cookie.MaxAge = 0
		cookie.Expires = time.Time{}
	}
	claims["exp"] = time.Now().Unix() + (jCC.LifeSpan)
}

// DeleteClaims just deletes the cookie.
func (jCC *ClaimsConfig) DeleteClaims(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: jCC.Cookie_name, MaxAge: -1})
}

/*
// Newclaims does nothing but I think would initialize the claims to some kind of basic, although this maybe be per-instance function.
func (ac *ClaimsConfig) NewClaims(seconds int) (claims jwt.Claims, err error) {
	//create basic claims, i guess. not important.
	return nil, nil
}
*/



/*
// Here is some reference stuff:

// const (
//    ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
//    ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
//    ValidationErrorSignatureInvalid                    // Signature validation failed

	// Standard Claim validation errors
//    ValidationErrorAudience      // AUD validation failed
//    ValidationErrorExpired       // EXP validation failed
//    ValidationErrorIssuedAt      // IAT validation failed
//    ValidationErrorIssuer        // ISS validation failed
//    ValidationErrorNotValidYet   // NBF validation failed
//    ValidationErrorId            // JTI validation failed
//    ValidationErrorClaimsInvalid // Generic claims validation error
// )

// Author's notes:


// In main or handler page: set Config.
// ***Not built: a context(s) can implement ServeHTTP directly, and each Handler defines its credentials

// ***a (Handler interface satisfying) type that takes a context(s) (via pointer/structure/array) (probably initialized by function)
// and implements your ServeHTTP function and therefor reuse context.

// ***a function that takes a context and returns a function with/ ServerHTTP signature.
// (same as above, different style, closers)

// some jtw notes- claims is a map[string].(JSON) (i don't want to use json)
// It's value is whatever we're using. Needs to make sense tho.

// We have exp - expiresat - Int64
//				 iat - issuedAt - Int64 (Don't use it before it's valid :-p)
//				 nbf - verifynot - Int64 (Don't verify it?)
// You might give someone a "session id" <-- an associate that with a security level
// Or track a state machine inside their cookie instead of on server
// Or give explicit access to a certain resource, through permission or lookup key
// I don't care what claims you add.
*/
