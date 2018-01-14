// Copyright 2013 The go-github AUTHORS. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gitee

import "context"

// UserEmail represents user's email address
type UserAddress struct {
	Aame   		*string `json:"name,omitempty"`
	Tel    		*string `json:"tel,omitempty"`
	Address    	*string `json:"address,omitempty"`
	Province    *string `json:"province,omitempty"`
	City    	*string `json:"city,omitempty"`
	ZipCode    	*string `json:"zip_code,omitempty"`
	Comment    	*string `json:"comment,omitempty"`
}

// ListEmails lists all email addresses for the authenticated user.
//
// GitHub API docs: https://developer.github.com/v3/users/emails/#list-email-addresses-for-a-user
func (s *UsersService) GetAddress(ctx context.Context) (*UserAddress, *Response, error) {
	u := "user/address"

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	uResp := new(UserAddress)
	resp, err := s.client.Do(ctx, req, uResp)
	if err != nil {
		return nil, resp, err
	}

	return uResp, resp, nil
}

// AddEmails adds email addresses of the authenticated user.
//
// GitHub API docs: https://developer.github.com/v3/users/emails/#add-email-addresses
func (s *UsersService) EditAddress(ctx context.Context, userAddress *UserAddress) (*User, *Response, error) {
	u := "user/address"
	req, err := s.client.NewRequest("PATCH", u, userAddress)
	if err != nil {
		return nil, nil, err
	}

	uResp := new(User)
	resp, err := s.client.Do(ctx, req, uResp)
	if err != nil {
		return nil, resp, err
	}

	return uResp, resp, nil
}
