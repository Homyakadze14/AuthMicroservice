package mailer

import (
	"encoding/base64"
	"log"
	"net/smtp"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
)

type Mailer struct {
	Auth smtp.Auth
	Addr string
}

func New(cfg *config.MailerConfig) *Mailer {
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	return &Mailer{
		Auth: auth,
		Addr: cfg.Addr,
	}
}

func (m *Mailer) SendMail(from, subject, body string, to string) error {
	msg := "To: " + to + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + base64.StdEncoding.EncodeToString([]byte(body))

	err := smtp.SendMail(m.Addr, m.Auth, from, []string{to}, []byte(msg))
	if err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}
