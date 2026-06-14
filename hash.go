package authkit

import "github.com/itsLeonB/sekure"

type hashService struct {
	inner sekure.HashService
}

func newHashService(cost int) *hashService {
	return &hashService{inner: sekure.NewHashService(cost)}
}

func (h *hashService) hash(password string) (string, error) {
	return h.inner.Hash(password)
}

func (h *hashService) verify(hash, password string) (bool, error) {
	return h.inner.CheckHash(hash, password)
}
