package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/alexedwards/argon2id"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	store "auth/internal"
	sec "auth/internal/security"
)

const (
	MSG_UNAUTHORIZED_ERR  = "Unauthorized: please authenticate."
	MSG_INTERNAL_ERR      = "A error occurred. Please contact a administrator."
	MSG_JSON_FORMAT_ERR   = "Invalid JSON format."
	MSG_USER_SCHEMA_ERR   = "Invalid user schema."
	MSG_UUID_ERR          = "Invalid UUID format."
	MSG_INPUT_ERR         = "Invalid input was provided."
	MSG_CREDENTIALS_ERR   = "Invalid credentials."
	MSG_TOKEN_ERR         = "Malformed token."
	MSG_TOKEN_MISSING_ERR = "Refresh token not provided."
	MSG_TOKEN_EXPIRED_ERR = "Token expired."
)

type AuthSuccess struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type ApiResponse struct {
	Error   bool   `json:"error"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type API struct {
	query     *store.Queries
	mux       *http.ServeMux
	validator *validator.Validate
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func NewApi(q *store.Queries) http.Handler {
	m := http.NewServeMux()
	api := API{
		query:     q,
		mux:       m,
		validator: validator.New(validator.WithRequiredStructEnabled()),
	}

	m.HandleFunc("GET /users", api.handleGetUsers)
	m.HandleFunc("POST /users", api.handleCreateUser)
	m.HandleFunc("PATCH /users/{userId}", api.handleUpdateUser)
	m.HandleFunc("DELETE /users/{userId}", api.handleDeleteUser)

	m.HandleFunc("GET /forbidden", api.handleForbidden)
	m.HandleFunc("POST /auth/refresh", api.handleAuthRefresh)
	m.HandleFunc("POST /auth", api.handleAuth)

	return &api
}

func (a *API) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := a.query.GetUsers(context.Background())
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	respondJson(w, http.StatusOK, ApiResponse{
		Error: false,
		Data:  rows,
	})
}

func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body store.CreateUserParams

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_JSON_FORMAT_ERR,
			Data:    err,
		})
		return
	}

	err = a.validator.Struct(body)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_USER_SCHEMA_ERR,
			Data:    err,
		})
		return
	}

	// hash password
	hashParams := &argon2id.Params{
		Memory:      128 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := argon2id.CreateHash(body.Password, hashParams)
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	body.Password = hash
	user, err := a.query.CreateUser(context.Background(), body)
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	respondJson(w, http.StatusCreated, ApiResponse{
		Error: false,
		Data:  user,
	})
}

func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userId := r.PathValue("userId")
	id, err := uuid.Parse(userId)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	var body store.UpdateUserParams
	err = json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_JSON_FORMAT_ERR,
			Data:    err,
		})
		return
	}

	err = a.validator.Struct(body)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_USER_SCHEMA_ERR,
			Data:    err,
		})
		return
	}

	body.ID = id
	user, err := a.query.UpdateUser(context.Background(), body)
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	respondJson(w, http.StatusOK, ApiResponse{
		Error: false,
		Data:  user,
	})
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	userId := r.PathValue("userId")
	id, err := uuid.Parse(userId)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_UUID_ERR,
			Data:    err,
		})
		return
	}

	err = a.query.DeleteUser(context.Background(), id)
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	respondJson(w, http.StatusOK, ApiResponse{
		Error: false,
		Data: struct {
			DeletedID uuid.UUID `json:"deletedId"`
		}{DeletedID: id},
	})
}

func (a *API) handleAuth(w http.ResponseWriter, r *http.Request) {
	type AuthInput struct {
		Email    string `json:"email"    validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	var input AuthInput
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_JSON_FORMAT_ERR,
			Data:    err,
		})
	}

	err = a.validator.Struct(input)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_INPUT_ERR,
			Data:    err,
		})
		return
	}

	user, err := a.query.GetUserByEmail(context.Background(), input.Email)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_CREDENTIALS_ERR,
			Data:    err,
		})
		return
	}

	// verify password
	match, err := argon2id.ComparePasswordAndHash(input.Password, user.Password)
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	if !match {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_CREDENTIALS_ERR,
			Data:    err,
		})
		return
	}

	accessToken, refreshToken, err := sec.GenTokenPair(&sec.TokenPayload{
		ID:    user.ID.String(),
		Email: user.Email,
	})
	if err != nil {
		respondJson(w, http.StatusInternalServerError, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err.Error(),
		})
		return
	}

	respondJson(w, http.StatusOK, ApiResponse{
		Error: false,
		Data: AuthSuccess{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	})
}

func (a *API) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refreshToken")
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_TOKEN_MISSING_ERR,
		})
		return
	}

	oldToken := cookie.String()[len("refreshToken="):]
	_, err = jwt.Parse(oldToken, func(tok *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			respondJson(w, http.StatusBadRequest, ApiResponse{
				Error:   true,
				Message: MSG_TOKEN_EXPIRED_ERR,
			})
			return
		}

		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_TOKEN_ERR,
			Data:    err.Error(),
		})
		return
	}

	accessToken, err := extractTokenStruct(r)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_TOKEN_ERR,
			Data:    err.Error(),
		})
		return
	}

	claims := accessToken.Claims.(*sec.JwtUserClaims)
	at, rt, err := sec.GenTokenPair(&sec.TokenPayload{
		ID:    claims.Subject,
		Email: claims.Email,
	})
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})
		return
	}

	respondJson(w, http.StatusOK, ApiResponse{
		Error: false,
		Data: AuthSuccess{
			AccessToken:  at,
			RefreshToken: rt,
		},
	})
}

func (a *API) handleForbidden(w http.ResponseWriter, r *http.Request) {
	isAuth, err := isAuthorized(r)
	if err != nil {
		respondJson(w, http.StatusBadRequest, ApiResponse{
			Error:   true,
			Message: MSG_TOKEN_ERR,
			Data:    err.Error(),
		})
		return
	}

	if !isAuth {
		respondJson(w, http.StatusForbidden, ApiResponse{
			Error:   true,
			Message: MSG_UNAUTHORIZED_ERR,
			Data:    err,
		})
		return
	}

	respondJson(w, http.StatusOK, ApiResponse{
		Error: false,
		Data:  isAuth,
	})
}

func respondJson(w http.ResponseWriter, s int, v ApiResponse) {
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		err_response, _ := json.Marshal(ApiResponse{
			Error:   true,
			Message: MSG_INTERNAL_ERR,
			Data:    err,
		})

		w.Write(err_response)
		return
	}

	w.WriteHeader(s)
	w.Write(data)
}

func isAuthorized(r *http.Request) (bool, error) {
	token, err := extractTokenStruct(r)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return false, nil
		}

		return false, err
	}

	if !token.Valid {
		return false, nil
	}

	return true, nil
}

func refreshToken(r *http.Request) (at, rt string, err error) {
	// expecting that the program has already
	// validated the token at this point in time
	token, err := extractTokenStruct(r)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return "", "", err
	}

	claims := token.Claims.(sec.JwtUserClaims)
	at, rt, err = sec.GenTokenPair(&sec.TokenPayload{
		ID:    claims.Subject,
		Email: claims.Email,
	})
	if err != nil {
		return "", "", err
	}

	// named returns for no reason hehe
	return
}

func extractTokenStruct(r *http.Request) (*jwt.Token, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return &jwt.Token{}, errors.New(MSG_TOKEN_ERR)
	}

	minLen := len("Bearer ")
	if len(h) < minLen {
		return &jwt.Token{}, errors.New(MSG_TOKEN_ERR)
	}

	t := h[minLen:]
	if t == "" {
		return &jwt.Token{}, errors.New(MSG_TOKEN_ERR)
	}

	nt, err := jwt.ParseWithClaims(t, &sec.JwtUserClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return &jwt.Token{}, errors.New(MSG_TOKEN_ERR)
	}

	return nt, nil
}
