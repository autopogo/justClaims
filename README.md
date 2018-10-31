# justClaims

Just claims gives you three functions. It's basically a wrapper for: www.gopkg.in/dgrijalva/jwt-go.v3. You don't need to import it, its type jwt.MapClaim is just a go Map.

  * `ReadClaims(http.ResponseWriter, *http.Request) (claims  jwt.MapClaims)`
  * `SetClaims(http.ResponseWriter, http.Request, jwt.MapClaims)`
  * `DeleteClaims(http.ResponseWriter)`

Remember to set its config structure. Godocs on the next commit.

# TODO:

AJ put this away...  

  * Interface/Basic API requirements for token stuff(<-- generalize it to a user-storage interface, include reading Auth)
  * Should Handlers share tokens? Create their own tokens? How do we negotiate security levels and mitigate collisions?
  * Error Handling (add custom errors)
  * Logging needs work, not sure if that's this repo tho (look at logging repo)
	* Tests (Test)

