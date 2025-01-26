package entities

type PwdLink struct {
	ID    int
	Email string
	Link  string
}

type ChPwdLink struct {
	ID       int
	Link     string
	Password string
}
