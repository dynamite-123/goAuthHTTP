package mongodb

import (
	"context"
	"fmt"
	"goAuthHTTP/internal/models"
	"goAuthHTTP/pkg/utils"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	client, err := CreateMongoClient()
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error connecting to the database")
	}
	defer client.Disconnect(ctx)

	filter := bson.M{"username": username}

	var user models.User
	err = client.Database("auth").Collection("users").FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, utils.ErrorHandler(err, "User not found. Incorrect username or password ")
		}
		return nil, utils.ErrorHandler(err, "Internal error")
	}
	return &user, nil
}

func AddUserToDB(ctx context.Context, userFromRequest *RegisterRequest) (*models.User, error) {
	client, err := CreateMongoClient()
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error connecting to mongodb")
	}
	defer client.Disconnect(ctx)

	// Create a new user model from the registration request
	modelUser := &models.User{
		Username: userFromRequest.Username,
		Email:    userFromRequest.Email,
		Password: userFromRequest.Password,
		Role:     "user", // Auto-set default role
	}

	// Hash the password before storing
	if modelUser.Password != "" {
		hashedPassword, err := utils.HashPassword(modelUser.Password)
		if err != nil {
			return nil, utils.ErrorHandler(err, "Error hashing password")
		}
		modelUser.Password = hashedPassword
	}

	res, err := client.Database("auth").Collection("users").InsertOne(ctx, modelUser)
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error inserting data into mongodb")
	}

	objectId, ok := res.InsertedID.(primitive.ObjectID)
	if ok {
		modelUser.Id = objectId.Hex()
	}

	return modelUser, nil
}

func ModifyUserRoleInDB(ctx context.Context, userIdFromReq, updatedRole string) error {
	client, err := CreateMongoClient()
	if err != nil {
		return utils.ErrorHandler(err, "Error connecting to mongodb")
	}
	defer client.Disconnect(ctx)

	objId, err := primitive.ObjectIDFromHex(userIdFromReq)
	if err != nil {
		return utils.ErrorHandler(err, "Invalid ID")
	}

	_, err = client.Database("auth").Collection("users").UpdateOne(ctx, bson.M{"_id": objId}, bson.M{"$set": bson.M{"role": updatedRole}})
	if err != nil {
		return utils.ErrorHandler(err, fmt.Sprintf("Error updating user with ID: %s", userIdFromReq))
	}

	return nil
}

// GetUserByEmail finds a user by their email address
func GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	client, err := CreateMongoClient()
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error connecting to the database")
	}
	defer client.Disconnect(ctx)

	filter := bson.M{"email": email}

	var user models.User
	err = client.Database("auth").Collection("users").FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // Return nil without error to indicate user doesn't exist
		}
		return nil, utils.ErrorHandler(err, "Internal error")
	}
	return &user, nil
}

// GetUserByGoogleId finds a user by their Google ID
func GetUserByGoogleId(ctx context.Context, googleId string) (*models.User, error) {
	client, err := CreateMongoClient()
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error connecting to the database")
	}
	defer client.Disconnect(ctx)

	filter := bson.M{"google_id": googleId}

	var user models.User
	err = client.Database("auth").Collection("users").FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // Return nil without error to indicate user doesn't exist
		}
		return nil, utils.ErrorHandler(err, "Internal error")
	}
	return &user, nil
}

// CreateGoogleUser creates a new user from Google OAuth data
func CreateGoogleUser(ctx context.Context, email, name, googleId, picture string) (*models.User, error) {
	client, err := CreateMongoClient()
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error connecting to mongodb")
	}
	defer client.Disconnect(ctx)

	// Create a new user model from Google OAuth data
	modelUser := &models.User{
		Username: name,
		Email:    email,
		GoogleId: googleId,
		Picture:  picture,
		Role:     "user", // Auto-set default role
		Password: "",     // No password for Google OAuth users
	}

	res, err := client.Database("auth").Collection("users").InsertOne(ctx, modelUser)
	if err != nil {
		return nil, utils.ErrorHandler(err, "Error inserting Google user into mongodb")
	}

	objectId, ok := res.InsertedID.(primitive.ObjectID)
	if ok {
		modelUser.Id = objectId.Hex()
	}

	return modelUser, nil
}

// UpdateUserGoogleInfo updates a user's Google ID and picture
func UpdateUserGoogleInfo(ctx context.Context, userId, googleId, picture string) error {
	client, err := CreateMongoClient()
	if err != nil {
		return utils.ErrorHandler(err, "Error connecting to mongodb")
	}
	defer client.Disconnect(ctx)

	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return utils.ErrorHandler(err, "Invalid ID")
	}

	update := bson.M{
		"$set": bson.M{
			"google_id": googleId,
			"picture":   picture,
		},
	}

	_, err = client.Database("auth").Collection("users").UpdateOne(ctx, bson.M{"_id": objId}, update)
	if err != nil {
		return utils.ErrorHandler(err, "Error updating user with Google information")
	}

	return nil
}
