package authkit

import "golang.org/x/crypto/bcrypt"

const defaultBcryptCost = 10

type hashService struct {
	cost int
}

func newHashService(cost int) *hashService {
	if cost <= 0 {
		cost = defaultBcryptCost
	}
	return &hashService{cost: cost}
}

func (h *hashService) hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func (h *hashService) verify(hashed, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
