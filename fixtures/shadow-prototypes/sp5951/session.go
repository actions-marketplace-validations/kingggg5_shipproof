package session

import "net/http"

func writeSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}
