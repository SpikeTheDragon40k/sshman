package sshutil

import (
	"errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// errAgentReadOnly is returned for every agent operation except List and
// Sign.
var errAgentReadOnly = errors.New("sshman agent: operation not permitted")

// readOnlyAgent exposes exactly one key for listing and signing (S-07). It
// refuses to add, remove, lock or unlock keys and supports no extensions, so
// a client of the socket cannot load other keys into it or tamper with the
// session's key.
type readOnlyAgent struct {
	kr agent.ExtendedAgent
}

var _ agent.ExtendedAgent = (*readOnlyAgent)(nil)

// newReadOnlyAgent returns an agent holding only rawKey.
func newReadOnlyAgent(rawKey any, comment string) (*readOnlyAgent, error) {
	kr, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		return nil, errors.New("keyring does not support extended operations")
	}
	if err := kr.Add(agent.AddedKey{PrivateKey: rawKey, Comment: comment}); err != nil {
		return nil, err
	}
	return &readOnlyAgent{kr: kr}, nil
}

func (a *readOnlyAgent) List() ([]*agent.Key, error) { return a.kr.List() }

func (a *readOnlyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.kr.Sign(key, data)
}

func (a *readOnlyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return a.kr.SignWithFlags(key, data, flags)
}

func (a *readOnlyAgent) Add(agent.AddedKey) error   { return errAgentReadOnly }
func (a *readOnlyAgent) Remove(ssh.PublicKey) error { return errAgentReadOnly }
func (a *readOnlyAgent) RemoveAll() error           { return errAgentReadOnly }
func (a *readOnlyAgent) Lock([]byte) error          { return errAgentReadOnly }
func (a *readOnlyAgent) Unlock([]byte) error        { return errAgentReadOnly }

// Signers is not reachable through the agent protocol; it is refused so the
// wrapper never hands out key material in-process either.
func (a *readOnlyAgent) Signers() ([]ssh.Signer, error) { return nil, errAgentReadOnly }

func (a *readOnlyAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
