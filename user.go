package cortex

import (
	"context"
	"net/http"
)

const usersURL = APIRoute + "/user"

// User represents a Cortex User
type User struct {
	Name         string   `json:"name"`
	CreatedAt    int64    `json:"createdAt"`
	Roles        []string `json:"roles"`
	CreatedBy    string   `json:"createdBy"`
	Organization string   `json:"organization"`
	Status       string   `json:"status"`
	UpdatedBy    string   `json:"updatedBy"`
	UpdatedAt    int64    `json:"updatedAt"`
	ID           string   `json:"id"`
	HasKey       bool     `json:"hasKey"`
	HasPassword  bool     `json:"hasPassword"`
}

// UserService is an interface for managing users
type UserService interface {
	Current(context.Context) (*User, *http.Response, error)
}

// UserServiceOp handles user specific methods from Cortex API
type UserServiceOp struct {
	client *Client
}

// Current retrieves a current user
func (u *UserServiceOp) Current(ctx context.Context) (*User, *http.Response, error) {
	req, err := u.client.NewRequest("GET", usersURL+"/current", nil)
	if err != nil {
		return nil, nil, err
	}

	var user User
	resp, err := u.client.Do(ctx, req, &user)
	if err != nil {
		return nil, nil, err
	}

	return &user, resp, nil
}
