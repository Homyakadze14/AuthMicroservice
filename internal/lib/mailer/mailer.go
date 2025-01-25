package mailer

type Mailer struct {
	activationUrl string
	mailSender    MailSender
}

type MailSender interface {
	SendMail(subject, body string, to string) error
}

func New(activationURL string, mailSender MailSender) *Mailer {
	return &Mailer{
		activationUrl: activationURL,
		mailSender:    mailSender,
	}
}

func (m *Mailer) SendActivationMail(email, link string) error {
	subject := "Activation link"
	body := "Your activation link: " + m.activationUrl + link
	err := m.mailSender.SendMail(subject, body, email)
	return err
}
