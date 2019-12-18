package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/go-chi/chi"
	chiware "github.com/go-chi/chi/middleware"
	"github.com/pressly/lg"
	"github.com/sirupsen/logrus"
)

var (
	version        = "dev"
	maxRequestSize = int64(20 * 1024) // ~10kB is expected size for 100*base64([64]byte) + ~framing

	errNoSecretKey         = errors.New("server config does not contain a key")
	errRequestTooLarge     = errors.New("request too large to process")
	errUnrecognizedRequest = errors.New("received unrecognized request type")
)

// Server is the main app service
type Server struct {
	ListenPort   int    `json:"listen_port,omitempty"`
	MaxTokens    int    `json:"max_tokens,omitempty"`
	DbConfigPath string `json:"db_config_path"`

	dbConfig DbConfig
	db       *sql.DB
	caches   map[string]CacheInterface
}

// DefaultServer on port
var DefaultServer = &Server{
	ListenPort: 2416,
}

// LoadConfigFile loads a file into conf and returns
func LoadConfigFile(filePath string) (Server, error) {
	conf := *DefaultServer
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}

var (
	errEmptyDbConfigPath = errors.New("no db config path specified")
)


// InitDbConfig reads os environment and update conf
func (c *Server) InitDbConfig() error {
	conf := DbConfig{
		ExpirationWindow: 7,
		RenewalWindow: 30,
		MaxConnection: 100,
	}

	// Heroku style
	if connectionURI := os.Getenv("DATABASE_URL"); connectionURI != "" {
		conf.ConnectionURI = os.Getenv("DATABASE_URL")
	}

	if maxConnection := os.Getenv("MAX_DB_CONNECTION"); maxConnection != "" {
		if count, err := strconv.Atoi(maxConnection); err == nil {
			conf.MaxConnection = count
		}
	}

	if expirationWindow := os.Getenv("EXPIRATION_WINDOW"); expirationWindow != "" {
		if count, err := strconv.Atoi(expirationWindow); err == nil {
			conf.ExpirationWindow = count
		}
	}

	if renewalWindow := os.Getenv("RENEWAL_WINDOW"); renewalWindow != "" {
		if count, err := strconv.Atoi(renewalWindow); err == nil {
			conf.RenewalWindow = count
		}
	}

	c.LoadDbConfig(conf)

	return nil
}

// SetupLogger creates a logger to use
func SetupLogger(ctx context.Context) (context.Context, *logrus.Logger) {
	logger := logrus.New()

	//logger.Formatter = &logrus.JSONFormatter{}

	// Redirect output from the standard logging package "log"
	lg.RedirectStdlogOutput(logger)
	lg.DefaultLogger = logger
	ctx = lg.WithLoggerContext(ctx, logger)
	return ctx, logger
}

func (c *Server) setupRouter(ctx context.Context, logger *logrus.Logger) (context.Context, *chi.Mux) {
	c.initDb()

	//govalidator.SetFieldsRequiredByDefault(true)

	r := chi.NewRouter()
	r.Use(chiware.RequestID)
	r.Use(chiware.Heartbeat("/"))
	r.Use(chiware.Timeout(60 * time.Second))
	r.Use(middleware.BearerToken)
	if logger != nil {
		// Also handles panic recovery
		r.Use(middleware.RequestLogger(logger))
	}

	r.Mount("/v1/blindedToken", c.tokenRouter())
	r.Mount("/v1/issuer", c.issuerRouter())
	r.Get("/metrics", middleware.Metrics())

	return ctx, r
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(ctx context.Context, logger *logrus.Logger) error {
	addr := fmt.Sprintf(":%d", c.ListenPort)
	srv := http.Server{Addr: addr, Handler: chi.ServerBaseContext(c.setupRouter(ctx, logger))}
	return srv.ListenAndServe()
}
