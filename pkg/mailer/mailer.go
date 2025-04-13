package mailer

import (
	"encoding/base64"
	"log"
	"net/smtp"

	"github.com/Homyakadze14/AuthMicroservice/internal/config"
)

type Mailer struct {
	auth smtp.Auth
	addr string
	from string
}

func New(cfg *config.MailerConfig) *Mailer {
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	return &Mailer{
		auth: auth,
		addr: cfg.Addr,
		from: cfg.Username,
	}
}

func (m *Mailer) SendMail(subject, body string, to string) error {
	msg := "To: " + to + "\r\n" +
		"From: " + m.from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + base64.StdEncoding.EncodeToString([]byte(body))

	err := smtp.SendMail(m.addr, m.auth, m.from, []string{to}, []byte(msg))
	if err != nil {
		log.Print(err.Error())
		return err
	}
	log.Printf("Email sent to %s", to)

	return nil
}
