package mongodb

import (
	"context"
	"crypto/tls"
	"goAuthHTTP/pkg/utils"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func CreateMongoClient() (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Fatal("MONGODB_URI environment variable is not set")
	}
	
	log.Printf("Connecting to MongoDB (URI length: %d chars)", len(mongoURI))

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	clientOptions := options.Client().
		ApplyURI(mongoURI).
		SetTLSConfig(tlsConfig).
		SetServerSelectionTimeout(10 * time.Second).
		SetConnectTimeout(10 * time.Second).
		SetSocketTimeout(10 * time.Second)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, utils.ErrorHandler(err, "Unable to connect to database")
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, utils.ErrorHandler(err, "Unable to ping the database")
	}

	log.Println("Connected to mongodb successfully")
	return client, nil
}
