// Code generated by mockery v2.50.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// Mailer is an autogenerated mock type for the Mailer type
type Mailer struct {
	mock.Mock
}

// SendActivationMail provides a mock function with given fields: email, link
func (_m *Mailer) SendActivationMail(email string, link string) error {
	ret := _m.Called(email, link)

	if len(ret) == 0 {
		panic("no return value specified for SendActivationMail")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(email, link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SendPwdMail provides a mock function with given fields: email, link
func (_m *Mailer) SendPwdMail(email string, link string) error {
	ret := _m.Called(email, link)

	if len(ret) == 0 {
		panic("no return value specified for SendPwdMail")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(email, link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewMailer creates a new instance of Mailer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMailer(t interface {
	mock.TestingT
	Cleanup(func())
}) *Mailer {
	mock := &Mailer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
