

// Author's notes:
// Gorilla's session half-implements RFC7519 (JWT), 
// ... signing and encryption, not validation.
// So no point in doing signing twice. We'll use setcookie + JWT
// RFC7519 wants us to use the Authorization header and... IDGAF, doesn't seem great.
// Only good for APIs


// In main or handler page: set AuthContext.
// ***a context(s) can implement ServeHTTP directly, and each Handler defines its credentials

// ***a type that takes a context(s) (via pointer/structure/array) 
// and implements your ServeHTTP function and therefor reuse context.

// ***a funciton that takes a context and returns a function with/ ServerHTTP signature.
// (same as above, different style)

// I mean, either we use what they gave us and do our best

// some jtw notes- claims is a map[string].(JSON) (i don't want to use json)
// It's value is whatever we're using. Needs to make sense tho.

// We have exp - expiresat - Int64
//				 iat - issuedAt - Int64 (Don't use it before it's valid :-p)
//				 nbf - verifynot - Int64 (Don't verify it?)
// being the most common.
// You might give someone a "session id" <-- an associate that with a security level
// Or track a state machine inside their cookie instead of on server
// Or give explicit access to a certain resource, through permission or lookup key
// I don't care what claims you add.
// This package was essentially conceived and architecuted by Keelin "kbw@autopogo.com" and then implemented by Andrew Pikul "ajp@autopogo.com" in a stunning reversal.

package server

import (
    "net/http"
    "time"

    "gopkg.in/dgrijalva/jwt-go.v3"
    log "project/logging"
)


type AuthContext struct {
    Jwt_key string
		Cookie_name string
		Cookie_persistent bool // close on window (UX hint) 
		Cookie_https bool // cookie only over https
		Cookie_server_only bool // cookie not accessible to client (prevents XSS in modernt browsers)
		MandatoryTokenRefresh bool // do we refresh the token/cookie if it's below a certain time
		MandatoryTokenRefreshThreshold float32  // whats that time
		LifeSpanNano int64 // seconds jwt+cookie have alive (if cookie persistent)
		// adapter for HTTPServe
		// adapter for HandlerFunc Factory (not a member)
}

// read claims. no cookie, return. claims invalid, return. if claims valid, and exp threshold, set cookie just in case.
func (aC *AuthContext) ReadJWT(w http.ResponseWriter, r *http.Request) (claims jwt.MapClaims, err error) {
	var t *jwt.Token
	if cookie, err := r.Cookie(aC.Cookie_name); err != nil {
		if (err == http.ErrNoCookie) {
			log.Enterf("ReadJWT: No Cookie, returning empty map");
			return make(map[string]interface{}), nil
		}
		log.Errorf("Weird error trying to find cookie");
		return nil, err
	} else {
		t, err = jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return []byte(aC.Jwt_key), nil
		})
		log.Enterf("ReadJWT: Token parsed")
	}
	if valid_ok := t.Valid; valid_ok {
		claims = t.Claims.(jwt.MapClaims)
		log.Enterf("ReadJWT: Claimers were valid, seeing if I should refresh")
		if _, ok := claims["exp"]; ok && aC.MandatoryTokenRefresh {
			//TODO if exp < MandatoryTokenRefreshThreshold time (chang _ to val)
			log.Enterf("ReadJWT: Refreshing token")
			aC.SetClaims(w, r, claims)
		} else {
			// 100 reasons why it might not exist, and therefore not our problem
		}
	} else {
		claims = make(map[string]interface{})
		log.Enterf("ReadJWT: Claims were invalid, returning empty map")
	}
	return
}

// if no passed cookie, try to pull it, or else create it, ultimately update it, encode it, and set it, using the claims you pass. It will update claims. 
func (aC *AuthContext) SetClaims(w http.ResponseWriter, r *http.Request, claims jwt.MapClaims){
	var cookie *http.Cookie
	var err error
	if cookie, err = r.Cookie(aC.Cookie_name); err != nil {
		if (err != http.ErrNoCookie) {
			log.Errorf("Error having to do with cookie retrieval: %v, err"); // log flooding?
		} else {
			log.Enterf("SetClaims: Making a new cookie")
			aC.SetCookieDefaults(cookie, claims);
		}
	} else {
		log.Enterf("SetClaims: Cookie exists, updating times")
		aC.updateExpiries(cookie, claims); //i'd want it to be a pointer but it's a reference type
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if ss, err := token.SignedString([]byte(aC.Jwt_key)); err != nil {
		log.Errorf("Couldn't unsign the encrypted string: %v", err)
	} else {
		log.Enterf("SetClaims: Attempting to set cookie")
		http.SetCookie(w, &http.Cookie{Name: aC.Cookie_name, Value: ss})

	}
	return
}

// create a cookie and update its stuff
func (aC *AuthContext) SetCookieDefaults(cookie *http.Cookie, claims jwt.MapClaims) {
	if (cookie == nil) {
		cookie = new(http.Cookie);
	}
	aC.updateExpiries(cookie, claims)
	cookie.HttpOnly = aC.Cookie_server_only
	cookie.Secure = aC.Cookie_https
}

// add the correct expiry to the cookie + jwt
func (aC *AuthContext) updateExpiries(cookie *http.Cookie, claims jwt.MapClaims) {
	if (aC.Cookie_persistent) {
		cookie.Expires = time.Now().Add(time.Duration(aC.LifeSpanNano))
		cookie.MaxAge = 0
	} else {
		cookie.MaxAge = 0
		cookie.Expires = time.Time{}
	}
	claims["exp"] = time.Now().Unix()
}

// delete the cookie
func (aC *AuthContext) DeleteCookie(w http.ResponseWriter) (err error) {
	http.SetCookie(w, &http.Cookie{Name: aC.Cookie_name, MaxAge: -1})
	// I left out things not set as optional but...
	// TODO return error
	return nil
}

// if you're going to refresh the cookie, place the claims you got here
func (ac *AuthContext) NewClaims(seconds int) (claims jwt.Claims, err error) {
	//create basic claims, i guess. not important.
	return nil, nil
}




/*
func Validate(next http.HandlerFunc) http.HandlerFunc { // I'm pretty sure this is what valid was supposed to do
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if r := recover(); r != nil {
                log.Errorf("***PANIC!*** %v", r)
            }
        }()

        log.Enterf("%v %s", r.Method, r.URL.EscapedPath())
        log.Printf("Claims: %v", *claims)
    })
}
*/
// TODO: writeFail
// if it's a bad token, you should respond with the proper header()... they may not care, so don't 401 everybody, but still. do they need to be authorized? can we treat it like first time? total rejection? let them know its a bad cookie tho
//	send WWW-Authenticate/401 and w/e info you want for the user
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
