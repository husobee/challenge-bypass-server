package server

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
)

type CachingConfig struct {
	Enabled       bool `json:"enabled"`
	ExpirationSec int  `json:"expirationSec"`
}

type DbConfig struct {
	ConnectionURI string        `json:"connectionURI"`
	CachingConfig CachingConfig `json:"caching"`
	MaxConnection int           `json:"maxConnection"`
	ExpirationWindow int        `json:"expirationWindow"`
	RenewalWindow int           `json:"renewalWindow"`
}

type Issuer struct {
	Id         string
	IssuerType string
	SigningKey *crypto.SigningKey
	MaxTokens  int
	ExpiresAt  time.Time
}

type Redemption struct {
	IssuerId string    `json:"issuerId"`
	Id         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Payload    string    `json:"payload"`
}

type CacheInterface interface {
	Get(k string) (interface{}, bool)
	SetDefault(k string, x interface{})
}

var (
	IssuerNotFoundError      = errors.New("Issuer with the given name does not exist")
	DuplicateRedemptionError = errors.New("Duplicate Redemption")
	RedemptionNotFoundError  = errors.New("Redemption with the given id does not exist")
)

func (c *Server) LoadDbConfig(config DbConfig) {
	c.dbConfig = config
}

func (c *Server) initDb() {
	cfg := c.dbConfig

	db, err := sql.Open("postgres", cfg.ConnectionURI)
	if err != nil {
		panic(err)
	}
	db.SetMaxOpenConns(cfg.MaxConnection)
	c.db = db

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file:///src/migrations",
		"postgres", driver)
	if err != nil {
		panic(err)
	}
	err = m.Migrate(3)
	if err != migrate.ErrNoChange && err != nil {
		panic(err)
	}

	if cfg.CachingConfig.Enabled {
		c.caches = make(map[string]CacheInterface)
		defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
		c.caches["issuers"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["redemptions"] = cache.New(defaultDuration, 2*defaultDuration)
	}
}

func (c *Server) fetchIssuer(issuerType string) (*Issuer, error) {
	if c.caches != nil {
		if cached, found := c.caches["issuers"].Get(issuerType); found {
			return cached.(*Issuer), nil
		}
	}

	rows, err := c.db.Query(
		`SELECT issuer_type, signing_key, max_tokens FROM issuers WHERE issuer_type=$1 ORDER BY expires_at, created_at DESC LIMIT 1`, issuerType)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if rows.Next() {
		var signingKey []byte
		var issuer = &Issuer{}
		if err := rows.Scan(&issuer.IssuerType, &signingKey, &issuer.MaxTokens); err != nil {
			return nil, err
		}

		issuer.SigningKey = &crypto.SigningKey{}
		err := issuer.SigningKey.UnmarshalText(signingKey)
		if err != nil {
			return nil, err
		}

		if c.caches != nil {
			c.caches["issuers"].SetDefault(issuerType, issuer)
		}

		return issuer, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, IssuerNotFoundError
}

func (c *Server) rotateIssuers() error {
	cfg := c.dbConfig

	rows, err := c.db.Query(
		`SELECT id, issuer_type, expires_at FROM issuers 
			WHERE expires_at != NULL 
			&& expires_at > NOW() - INTERVAL '$1 day'
			&& expires_at < NOW()
		FOR UPDATE SKIP LOCKED`, cfg.ExpirationWindow,
	)
	if err != nil {
		return err
	}
	if rows.Next() {
		var issuer = &Issuer{};
		if err := rows.Scan(&issuer.Id, &issuer.IssuerType, &issuer.SigningKey, &issuer.ExpiresAt); err != nil {
			return err
		}
		c.createIssuer(issuer.IssuerType, issuer.MaxTokens, issuer.ExpiresAt.AddDate(0, 0, c.dbConfig.RenewalWindow))
	}

	defer rows.Close()

	return nil
}

func (c *Server) retireIssuers() error {
	rows, err := c.db.Query(`
		SELECT id FROM issuers
		WHERE expires_at != NULL
		expires_at > now()
	`)
	if err != nil {
		return err
	}

	if rows.Next() {
		var issuer = &Issuer{};
		if err := rows.Scan(&issuer.Id); err != nil {
			return err
		}
		c.db.Query(`
			CREATE TABLE redemptions_` + issuer.Id + ` PARTITION OF redemptions
			FOR VALUES IN ('$1')
		`, issuer.Id)
	}
	defer rows.Close()

	return nil
}

func (c *Server) createIssuer(issuerType string, maxTokens int, expiresAt time.Time) error {
	if maxTokens == 0 {
		maxTokens = 40
	}

	signingKey, err := crypto.RandomSigningKey()
	if err != nil {
		return err
	}

	signingKeyTxt, err := signingKey.MarshalText()
	if err != nil {
		return err
	}

	rows, err := c.db.Query(
		`INSERT INTO issuers(issuer_type, signing_key, max_tokens, expires_at) VALUES ($1, $2, $3, $4)`, 
		issuerType, 
		signingKeyTxt,
		maxTokens, 
		expiresAt.Format("2006-01-02"),
	)
	if err != nil {
		return err
	}

	defer rows.Close()
	return nil
}

func (c *Server) redeemToken(issuerType string, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		return err
	}

	rows, err := c.db.Query(
		`INSERT INTO redemptions(id, issuer_type, ts, payload) VALUES ($1, $2, NOW(), $3)`, preimageTxt, issuerType, payload)

	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code == "23505" { // unique constraint violation
			return DuplicateRedemptionError
		}
		return err
	}

	defer rows.Close()
	return nil
}

func (c *Server) fetchRedemption(issuerId, id string) (*Redemption, error) {
	if c.caches != nil {
		if cached, found := c.caches["redemptions"].Get(fmt.Sprintf("%s:%s", issuerId, id)); found {
			return cached.(*Redemption), nil
		}
	}

	rows, err := c.db.Query(
		`SELECT id, issuer_id, ts, payload FROM redemptions WHERE id = $1 AND issuer_id = $2`, id, issuerId)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if rows.Next() {
		var redemption = &Redemption{}
		if err := rows.Scan(&redemption.Id, &redemption.IssuerId, &redemption.Timestamp, &redemption.Payload); err != nil {
			return nil, err
		}

		if c.caches != nil {
			c.caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", issuerId, id), redemption)
		}

		return redemption, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, RedemptionNotFoundError
}
