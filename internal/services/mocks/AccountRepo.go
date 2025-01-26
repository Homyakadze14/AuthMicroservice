// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import (
	context "context"

	entities "github.com/Homyakadze14/AuthMicroservice/internal/entities"
	mock "github.com/stretchr/testify/mock"
)

// AccountRepo is an autogenerated mock type for the AccountRepo type
type AccountRepo struct {
	mock.Mock
}

// Create provides a mock function with given fields: ctx, account
func (_m *AccountRepo) Create(ctx context.Context, account *entities.Account) (int, error) {
	ret := _m.Called(ctx, account)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 int
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *entities.Account) (int, error)); ok {
		return rf(ctx, account)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *entities.Account) int); ok {
		r0 = rf(ctx, account)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *entities.Account) error); ok {
		r1 = rf(ctx, account)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByEmail provides a mock function with given fields: ctx, email
func (_m *AccountRepo) GetByEmail(ctx context.Context, email string) (*entities.Account, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for GetByEmail")
	}

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*entities.Account, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *entities.Account); ok {
		r0 = rf(ctx, email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByUserID provides a mock function with given fields: ctx, uid
func (_m *AccountRepo) GetByUserID(ctx context.Context, uid string) (*entities.Account, error) {
	ret := _m.Called(ctx, uid)

	if len(ret) == 0 {
		panic("no return value specified for GetByUserID")
	}

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*entities.Account, error)); ok {
		return rf(ctx, uid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *entities.Account); ok {
		r0 = rf(ctx, uid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, uid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetByUsername provides a mock function with given fields: ctx, username
func (_m *AccountRepo) GetByUsername(ctx context.Context, username string) (*entities.Account, error) {
	ret := _m.Called(ctx, username)

	if len(ret) == 0 {
		panic("no return value specified for GetByUsername")
	}

	var r0 *entities.Account
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*entities.Account, error)); ok {
		return rf(ctx, username)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *entities.Account); ok {
		r0 = rf(ctx, username)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entities.Account)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdatePwdByEmail provides a mock function with given fields: ctx, email, password
func (_m *AccountRepo) UpdatePwdByEmail(ctx context.Context, email string, password string) error {
	ret := _m.Called(ctx, email, password)

	if len(ret) == 0 {
		panic("no return value specified for UpdatePwdByEmail")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, email, password)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewAccountRepo creates a new instance of AccountRepo. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAccountRepo(t interface {
	mock.TestingT
	Cleanup(func())
}) *AccountRepo {
	mock := &AccountRepo{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
