package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("usage: interop <token-url> <client-id> <client-secret>")
		os.Exit(2)
	}
	config := &clientcredentials.Config{
		ClientID:     os.Args[2],
		ClientSecret: os.Args[3],
		TokenURL:     os.Args[1],
		AuthStyle:    oauth2.AuthStyleInHeader,
	}
	token, err := config.Token(context.Background())
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("token_type:", token.TokenType)
	fmt.Println("access_token_present:", len(token.AccessToken) > 0)
}
