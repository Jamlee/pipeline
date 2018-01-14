// Copyright 2013 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gitee

import "context"

// UserEmail represents user's email address
type UserEmail struct {
	Email 				*string `json:"email,omitempty"`
	UnconfirmedEmail  	*string  `json:"unconfirmed_email,omitempty"`
}

// ListEmails lists all email addresses for the authenticated user.
//
// GitHub API docs: https://developer.github.com/v3/users/emails/#list-email-addresses-for-a-user
func (s *UsersService) GetEmail(ctx context.Context) (*UserEmail, *Response, error) {
	u := "user/emails"

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	uResp := new(UserEmail)
	resp, err := s.client.Do(ctx, req, uResp)
	if err != nil {
		return nil, resp, err
	}

	return uResp, resp, nil
}

// AddEmails adds email addresses of the authenticated user.
//
// GitHub API docs: https://developer.github.com/v3/users/emails/#add-email-addresses
func (s *UsersService) AddEmail(ctx context.Context, email *UserEmail) (*UserEmail, *Response, error) {
	u := "user/emails"

	req, err := s.client.NewRequest("POST", u, email)
	if err != nil {
		return nil, nil, err
	}

	uResp := new(UserEmail)
	resp, err := s.client.Do(ctx, req, uResp)
	if err != nil {
		return nil, resp, err
	}

	return uResp, resp, nil
}

// DeleteEmails deletes email addresses from authenticated user.
//
// GitHub API docs: https://developer.github.com/v3/users/emails/#delete-email-addresses
func (s *UsersService) DeleteEmail(ctx context.Context) (bool, *Response, error) {
	u := "user/unconfirmed_email"
	req, err := s.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return false,nil, err
	}

	resp, err := s.client.Do(ctx, req, nil)
	ok, err := parseBoolResponse(err)
	return ok, resp, err
}
