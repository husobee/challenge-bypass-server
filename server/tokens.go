package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/go-chi/chi"
)

type blindedTokenIssueRequest struct {
	BlindedTokens []*crypto.BlindedToken `json:"blinded_tokens"`
}

type blindedTokenIssueResponse struct {
	BatchProof   *crypto.BatchDLEQProof `json:"batch_proof"`
	SignedTokens []*crypto.SignedToken  `json:"signed_tokens"`
}

type blindedTokenRedeemRequest struct {
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
	Payload       string                        `json:"payload"`
}

func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.getLatestIssuer(issuerType)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenIssueRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			return handlers.WrapError("Could not parse the request body", err)
		}

		if request.BlindedTokens == nil {
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, issuer.SigningKey)
		if err != nil {
			return &handlers.AppError{
				Error:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}

		err = json.NewEncoder(w).Encode(blindedTokenIssueResponse{proof, signedTokens})
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuers, appErr := c.getIssuers(issuerType)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenRedeemRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			return handlers.WrapError("Could not parse the request body", err)
		}

		if request.TokenPreimage == nil || request.Signature == nil {
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		var verified = false
		var verifiedIssuer = &Issuer{}
		for _, issuer := range *issuers {
			if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, []*crypto.SigningKey{issuer.SigningKey}); err != nil {
				verified = false
			} else {
				verified = true
				verifiedIssuer = &issuer
				break
			}
		}

		if !verified {
			return &handlers.AppError{
				Message: "Could not verify that token redemption is valid",
				Code:    http.StatusBadRequest,
			}
		}

		if err := c.redeemToken(verifiedIssuer, request.TokenPreimage, request.Payload); err != nil {
			if err == errDuplicateRedemption {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &handlers.AppError{
				Error:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}

		}
	}
	return nil
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	if issuerID := chi.URLParam(r, "id"); issuerID != "" {
		tokenID := r.FormValue("tokenId")

		issuer, err := c.fetchIssuer(issuerID)
		fmt.Println(err)
		if err != nil {
			return &handlers.AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		if issuer.Version == 2 {
			redemption, err := c.fetchRedemptionV2(issuer, tokenID)
			if err != nil {
				if err == errRedemptionNotFound {
					return &handlers.AppError{
						Message: err.Error(),
						Code:    http.StatusBadRequest,
					}
				}
				return &handlers.AppError{
					Error:   err,
					Message: "Could not check token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
			err = json.NewEncoder(w).Encode(redemption)
			if err != nil {
				panic(err)
			}
			return nil
		}

		redemption, err := c.fetchRedemption(issuer.IssuerType, tokenID)
		if err != nil {
			if err == errRedemptionNotFound {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				}
			}
			return &handlers.AppError{
				Error:   err,
				Message: "Could not check token redemption",
				Code:    http.StatusInternalServerError,
			}
		}

		err = json.NewEncoder(w).Encode(redemption)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (c *Server) tokenRouter() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method(http.MethodPost, "/{type}", middleware.InstrumentHandler("IssueTokens", handlers.AppHandler(c.blindedTokenIssuerHandler)))
	r.Method(http.MethodPost, "/{type}/redemption/", middleware.InstrumentHandler("RedeemTokens", handlers.AppHandler(c.blindedTokenRedeemHandler)))
	r.Method(http.MethodGet, "/{id}/redemption/", middleware.InstrumentHandler("CheckToken", handlers.AppHandler(c.blindedTokenRedemptionHandler)))
	return r
}
