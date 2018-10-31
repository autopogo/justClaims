/*
Package justClaims provides an API for extraordinarily simple access of token claims in a cookie. It assumes one token, one cookie. It, like other just* packages, is configured through a structure and uses that information to define its behavior. It is an extraordinarily simple package.

See https://github.com/autopogo/GoServerSkeleton for a basic usage
*/
package justClaims

import (
    "net/http"
    "time"

    "gopkg.in/dgrijalva/jwt-go.v3"
    log "github.com/autopogo/justLogging"
)

// JustClaimsConfig is a configuration structure to set constants needed when the server is live.
type JustClaimsConfig struct {
    Jwt_key string // Jwt_key defines the JWT Signing Hash Key
		Cookie_name string // Cookie_name defines the name of the cookie to store it in
		Cookie_persistent bool // If this is set to false, no expiry is set, which means it expires on window close (a UX hint)
		Cookie_https bool // Cookie fails except over HTTPS
		Cookie_server_only bool // Cookie not accessible to client (prevents XSS in modern browsers)
		MandatoryTokenRefresh bool // The token/cookie will be autorefresh on read
		MandatoryTokenRefreshThreshold float32  // Autorefresh will only occur if it is < this * LifeSpanNano
		LifeSpanNano int64 // Nanoseconds jwt+cookie have alive (if cookie persistent)
		// TODO: adapter for HTTPServe
		// TODO: adapter for HandlerFunc Factory (not a member)
}
func (jCC *JustClaimsConfig) GetVersion() (version string) {
	return "hello"

}
// ReadJWT reads and returns claims, right now a MapClaims
// It returns empty claims if there is no cookie or if they were invalid
// It will refresh them according to MandatoryTokenRefresh*
func (jCC *JustClaimsConfig) ReadClaims(w http.ResponseWriter, r *http.Request) (claims jwt.MapClaims, err error) {
	var t *jwt.Token

	// Grabbing cookie
	if cookie, err := r.Cookie(jCC.Cookie_name); err != nil {
		if (err == http.ErrNoCookie) {
			log.Enterf("ReadJWT: No Cookie, returning empty map");
			return make(map[string]interface{}), nil // initializes the map... ?
		}
		log.Errorf("Weird error trying to find cookie");
		return nil, err
	} else {
		t, err = jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) { // parses... ?
			return []byte(jCC.Jwt_key), nil
		})
		log.Enterf("ReadJWT: Token parsed")
	}

	// Checking if valid
	if valid_ok := t.Valid; valid_ok { // how does it know what valid to call?
		claims = t.Claims.(jwt.MapClaims)
		log.Enterf("ReadJWT: Claimers were valid, seeing if I should refresh")

		// relies on MapClaims interface, must be typeswitch?
		// if the implementer builds a custom claims type- not a map, but a struct, whatever, they
		// will have to supply a function to get the exp date
		if _, ok := claims["exp"]; ok && jCC.MandatoryTokenRefresh {
			//TODO if exp < MandatoryTokenRefreshThreshold time (chang _ to val)
			log.Enterf("ReadJWT: Refreshing token")
			jCC.SetClaims(w, r, claims)
		}
	} else {
		claims = make(map[string]interface{}) // again, initializing the map ...?
		log.Enterf("ReadJWT: Claims were invalid, returning empty map")
	}
	return
}

// SetClaims will sign and set the claims based on defaults set in JustClaimsConfig
func (jCC *JustClaimsConfig) SetClaims(w http.ResponseWriter, r *http.Request, claims jwt.MapClaims){
	cookie := &http.Cookie{ Name: jCC.Cookie_name,
		Secure: jCC.Cookie_https,
		HttpOnly: jCC.Cookie_server_only }
	jCC.updateExpiries(cookie, claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if ss, err := token.SignedString([]byte(jCC.Jwt_key)); err != nil {
		log.Errorf("Couldn't unsign the encrypted string: %v", err)
	} else {
		log.Enterf("SetClaims: Attempting to set cookie")
		cookie.Value = ss;
		http.SetCookie(w, cookie)
	}
	return
}


// updateExperies just handles writing time values to the cookie and JWT
func (jCC *JustClaimsConfig) updateExpiries(cookie *http.Cookie, claims jwt.MapClaims) {
	if (jCC.Cookie_persistent) {
		cookie.Expires = time.Now().Add(time.Duration(jCC.LifeSpanNano))
		cookie.MaxAge = 0
	} else {
		cookie.MaxAge = 0
		cookie.Expires = time.Time{}
	}
	claims["exp"] = time.Now().Unix()
}

// DeleteClaims just deletes the cookie
func (jCC *JustClaimsConfig) DeleteClaims(w http.ResponseWriter) (err error) {
	http.SetCookie(w, &http.Cookie{Name: jCC.Cookie_name, MaxAge: -1})
	// I left out things not set as optional but...
	// TODO return error
	return nil
}
/*
// Newclaims does nothing but I think would initialize the claims to some kind of basic, although this maybe be per-instance function.
func (ac *JustClaimsConfig) NewClaims(seconds int) (claims jwt.Claims, err error) {
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


// In main or handler page: set JustClaimsConfig.
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
