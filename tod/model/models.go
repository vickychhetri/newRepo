package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var (
	Db           *gorm.DB         // Global database connection
	JwtSecretKey []byte           // Secret key used for JWT signing
	TokenTTL     = time.Hour * 24 // Token time-to-live (24 hours)
)

// User represents a registered user in the system.
type User struct {
	ID       uint   `gorm:"primaryKey;comment:Primary key" json:"id"`
	Username string `gorm:"uniqueIndex;not null;type:varchar(100);comment:Unique username for login" json:"username"`
	Password string `gorm:"not null;type:varchar(255);comment:Hashed password" json:"-"`
	Tasks    []Task `gorm:"foreignKey:UserId;comment:Tasks owned by the user" json:"tasks,omitempty"`
}

// Claims represents custom JWT claims containing the user ID.
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

// Task represents an individual task created by a user.
type Task struct {
	ID          uint      `gorm:"primaryKey;comment:Primary key" json:"id"`
	Title       string    `gorm:"not null;type:varchar(150);comment:Task title" json:"title"`
	Description string    `gorm:"type:varchar(500);comment:Optional detailed task description" json:"description"`
	Completed   bool      `gorm:"default:false;comment:Completion status" json:"completed"`
	CreatedAt   time.Time `gorm:"comment:Record creation time" json:"created_at"`
	UpdatedAt   time.Time `gorm:"comment:Record last update time" json:"updated_at"`
	UserId      uint      `gorm:"not null;comment:Foreign key referencing users.id" json:"user_id"`
	User        User      `gorm:"foreignKey:UserId" json:"user"`
}
