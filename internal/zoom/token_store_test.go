package zoom

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMemoryTokenStore(t *testing.T) {
	// Create a token store
	store := NewMemoryTokenStore()

	// Create a token
	token := &Token{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save the token
	err := store.SaveToken(token)
	assert.NoError(t, err)

	// Get the token
	retrievedToken, err := store.GetToken()
	assert.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrievedToken.AccessToken)
	assert.Equal(t, token.RefreshToken, retrievedToken.RefreshToken)
	assert.Equal(t, token.TokenType, retrievedToken.TokenType)
	assert.Equal(t, token.Expiry.Unix(), retrievedToken.Expiry.Unix())

	// Delete the token
	err = store.DeleteToken()
	assert.NoError(t, err)

	// Verify token is deleted
	_, err = store.GetToken()
	assert.Error(t, err)
	assert.Equal(t, "no token found", err.Error())
}

func TestFileTokenStore(t *testing.T) {
	// Create a temporary directory for the test
	tempDir, err := os.MkdirTemp("", "zoom-token-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a token file path
	tokenFilePath := filepath.Join(tempDir, "token.json")

	// Create a token store
	store := NewFileTokenStore(tokenFilePath)

	// Create a token
	token := &Token{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Test initial state (no token)
	_, err = store.GetToken()
	assert.Error(t, err)
	assert.Equal(t, "no token found", err.Error())

	// Save the token
	err = store.SaveToken(token)
	assert.NoError(t, err)

	// Verify the file exists
	_, err = os.Stat(tokenFilePath)
	assert.NoError(t, err)

	// Get the token
	retrievedToken, err := store.GetToken()
	assert.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrievedToken.AccessToken)
	assert.Equal(t, token.RefreshToken, retrievedToken.RefreshToken)
	assert.Equal(t, token.TokenType, retrievedToken.TokenType)
	assert.Equal(t, token.Expiry.Unix(), retrievedToken.Expiry.Unix())

	// Delete the token
	err = store.DeleteToken()
	assert.NoError(t, err)

	// Verify the file no longer exists
	_, err = os.Stat(tokenFilePath)
	assert.True(t, os.IsNotExist(err))

	// Verify token is deleted
	_, err = store.GetToken()
	assert.Error(t, err)
	assert.Equal(t, "no token found", err.Error())
}

func TestMockTokenStore(t *testing.T) {
	// Create a token store
	store := NewMockTokenStore()

	// Create a token
	token := &Token{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
		TokenType:    "bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save the token
	err := store.SaveToken(token)
	assert.NoError(t, err)

	// Get the token
	retrievedToken, err := store.GetToken()
	assert.NoError(t, err)
	assert.Equal(t, token.AccessToken, retrievedToken.AccessToken)
	assert.Equal(t, token.RefreshToken, retrievedToken.RefreshToken)
	assert.Equal(t, token.TokenType, retrievedToken.TokenType)
	assert.Equal(t, token.Expiry.Unix(), retrievedToken.Expiry.Unix())

	// Delete the token
	err = store.DeleteToken()
	assert.NoError(t, err)

	// Verify token is deleted
	_, err = store.GetToken()
	assert.Error(t, err)
	assert.Equal(t, "no token found", err.Error())
} 