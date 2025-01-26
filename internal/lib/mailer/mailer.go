package mailer

import "github.com/Homyakadze14/AuthMicroservice/internal/config"

type Mailer struct {
	links      config.BaseLinksConfig
	mailSender MailSender
}

type MailSender interface {
	SendMail(subject, body string, to string) error
}

func New(links config.BaseLinksConfig, mailSender MailSender) *Mailer {
	return &Mailer{
		links:      links,
		mailSender: mailSender,
	}
}

func (m *Mailer) SendActivationMail(email, link string) error {
	subject := "Activation link"
	body := "Your activation link: " + m.links.ActivationUrl + link
	err := m.mailSender.SendMail(subject, body, email)
	return err
}

func (m *Mailer) SendPwdMail(email, link string) error {
	subject := "Change password"
	body := "Your change password link: " + m.links.ChangePasswordUrl + link
	err := m.mailSender.SendMail(subject, body, email)
	return err
}
