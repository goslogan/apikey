package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dchest/uniuri"
	"github.com/goslogan/grsearch"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type KeyPermissions uint32
type APIKey struct {
	Permissions KeyPermissions `json:"permissions"`
	Expires     time.Time      `json:"expires"`
	Created     time.Time      `json:"created"`
	Owner       string         `json:"owner"`
	Email       string         `json:"email"`
	CreatedBy   string         `json:"createdBy"`
	Comment     string         `json:"comment"`
}

const oneHundredAndEightyDays = 24 * 180
const DefaultKeyExpiry = time.Duration(time.Hour * oneHundredAndEightyDays)
const keyPrefix = "key"

// Returns the permissions associated with a raw key if it exists. Returns an
// empty string if not
func GetKey(ctx context.Context, client *redis.Client, logger zerolog.Logger, key string) (*APIKey, error) {
	rKey := redisKey(key)
	cmd := client.JSONGet(ctx, rKey)
	l := logger.With().Str("key", key).Str("redisKey", rKey).Logger()
	if cmd.Err() != nil && cmd.Err() != redis.Nil {
		logger.Debug().Err(cmd.Err()).Msg("error calling JSON.GET")
		return nil, cmd.Err()
	}

	if cmd.Val() == "" {
		l.Debug().Msg("key not found")
		return nil, redis.Nil
	}

	apiKey := APIKey{}

	return &apiKey, json.Unmarshal([]byte(cmd.Val()), &apiKey)
}

// NewKeyWithExpiry returns a random string to be used as a key with the specified permissions and expiry
func NewKeyWithExpiry(ctx context.Context, client *grsearch.Client, logger zerolog.Logger, owner, email, creator, comment string, permissions KeyPermissions, expiry time.Duration) (string, *APIKey, error) {
	apiKey := APIKey{
		Owner:       owner,
		Email:       email,
		Comment:     comment,
		CreatedBy:   creator,
		Expires:     time.Now().Add(expiry),
		Created:     time.Now(),
		Permissions: permissions}

	key := uniuri.NewLen(uniuri.UUIDLen)

	err := client.JSONSet(ctx, redisKey(key), "$", apiKey).Err()
	if err != nil {
		return "", nil, err
	} else {
		return key, &apiKey, client.Expire(ctx, redisKey(key), expiry).Err()
	}
}

// NewKey returns a random string to be used as a key with the specified permissions and default expirty
func NewKey(ctx context.Context, client *grsearch.Client, logger zerolog.Logger, owner, email, creator, comment string, permissions KeyPermissions) (string, *APIKey, error) {
	return NewKeyWithExpiry(ctx, client, logger, owner, email, creator, comment, permissions, DefaultKeyExpiry)
}

// hashKey hashes a new key
func HashedKey(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hex.EncodeToString(hash.Sum(nil))
}

// redisKey returns the redis key for a given raw key.
func redisKey(key string) string {
	return fmt.Sprintf("%s:%s", keyPrefix, HashedKey(key))
}

// Can returns true if a Key has a particular permission
func Can(ctx context.Context, client *redis.Client, logger zerolog.Logger, key string, perm KeyPermissions) (bool, error) {
	l := logger.With().Str("key", key).Str("redisKey", redisKey(key)).Logger()
	apiKey, err := GetKey(ctx, client, logger, key)
	if err != nil {

		l.Debug().Err(err).Msg("error getting the key")
		return false, err
	} else {
		result := apiKey.Permissions.can(perm)
		logger.Debug().Bool("result", result).Uint16("requested", uint16(perm)).Interface("APIKey", apiKey).Msg("testing permissions")
		return result, nil
	}
}

// can returns true if a permission contains a given permission
func (p KeyPermissions) can(perm KeyPermissions) bool {
	return p&perm == perm
}
