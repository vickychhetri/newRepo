package auth

import (
	"time"
	"tod/model" // Import the model package (likely contains Claims structure, TokenTTL, JwtSecretKey)

	"github.com/golang-jwt/jwt/v5" // JWT package for creating and verifying tokens
	"golang.org/x/crypto/bcrypt"   // Bcrypt package for securely hashing passwords
)

// GenerateToken creates a JWT token for the user with a given user ID.
func GenerateToken(userId uint) (string, error) {
	// Create a custom Claims struct, embedding jwt.RegisteredClaims
	claims := &model.Claims{
		UserID: userId, // User's ID to be included in the token's claims

		// JWT RegisteredClaims defines standard fields in a JWT like expiry time, issued at time, etc.
		RegisteredClaims: jwt.RegisteredClaims{
			// Set the expiration time of the token. The token will expire after a predefined duration (TokenTTL).
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(model.TokenTTL)), // TokenTTL is expected to be set in the model package
			IssuedAt:  jwt.NewNumericDate(time.Now()),                     // Set the issued time as the current time
		},
	}

	// Create the token using the claims and the ES256 signing method (elliptic curve algorithm)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign and generate the final token string using a secret key (JwtSecretKey) defined in the model package
	return token.SignedString(model.JwtSecretKey)
}

// HashPassword hashes a plain-text password using bcrypt.
func HashPassword(pass string) (string, error) {
	// bcrypt.GenerateFromPassword hashes the password with the default cost (typically 10)
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return string(b), err
}

// CheckPassword compares a hashed password with a plain-text password to see if they match.
func CheckPassword(hash, pass string) error {
	// bcrypt.CompareHashAndPassword compares the given hash and plain password
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass))
}
