// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_Success(t *testing.T) {
	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	// Generate audit log
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr-data",
		"result-meta-xdr-data",
		[]string{"event1", "event2"},
		[]string{"log1", "log2"},
		privateKeyHex,
	)

	require.NoError(t, err)
	assert.NotNil(t, log)
	assert.Equal(t, "1.0.0", log.Version)
	assert.Equal(t, "test-tx-hash", log.TransactionHash)
	assert.NotEmpty(t, log.TraceHash)
	assert.NotEmpty(t, log.Signature)
	assert.Equal(t, hex.EncodeToString(publicKey), log.PublicKey)
	assert.Equal(t, "envelope-xdr-data", log.Payload.EnvelopeXdr)
	assert.Equal(t, "result-meta-xdr-data", log.Payload.ResultMetaXdr)
	assert.Equal(t, []string{"event1", "event2"}, log.Payload.Events)
	assert.Equal(t, []string{"log1", "log2"}, log.Payload.Logs)
}

func TestGenerate_InvalidPrivateKey(t *testing.T) {
	tests := []struct {
		name          string
		privateKeyHex string
		expectError   string
	}{
		{
			name:          "invalid hex",
			privateKeyHex: "not-hex",
			expectError:   "invalid private key hex",
		},
		{
			name:          "wrong length",
			privateKeyHex: "abcd",
			expectError:   "invalid private key length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := Generate(
				"test-tx-hash",
				"envelope-xdr",
				"result-meta-xdr",
				[]string{},
				[]string{},
				tt.privateKeyHex,
			)

			assert.Nil(t, log)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestGenerate_FromSeed(t *testing.T) {
	// Generate a seed (32 bytes)
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	require.NoError(t, err)

	seedHex := hex.EncodeToString(seed)

	// Generate audit log from seed
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr",
		"result-meta-xdr",
		[]string{"event1"},
		[]string{"log1"},
		seedHex,
	)

	require.NoError(t, err)
	assert.NotNil(t, log)
	assert.NotEmpty(t, log.Signature)
}

func TestVerify_Success(t *testing.T) {
	// Generate a test key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	// Generate audit log
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr-data",
		"result-meta-xdr-data",
		[]string{"event1", "event2"},
		[]string{"log1"},
		privateKeyHex,
	)
	require.NoError(t, err)

	// Verify the log
	err = Verify(log)
	assert.NoError(t, err)
}

func TestVerify_TamperedPayload(t *testing.T) {
	// Generate a test key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	// Generate audit log
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr-data",
		"result-meta-xdr-data",
		[]string{"event1"},
		[]string{"log1"},
		privateKeyHex,
	)
	require.NoError(t, err)

	// Tamper with the payload
	log.Payload.Events = []string{"tampered-event"}

	// Verification should fail
	err = Verify(log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trace hash mismatch")
}

func TestVerify_InvalidSignature(t *testing.T) {
	// Generate a test key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	// Generate audit log
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr-data",
		"result-meta-xdr-data",
		[]string{"event1"},
		[]string{"log1"},
		privateKeyHex,
	)
	require.NoError(t, err)

	// Tamper with the signature
	log.Signature = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	// Verification should fail
	err = Verify(log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerify_InvalidPublicKey(t *testing.T) {
	log := &AuditLog{
		PublicKey: "not-hex",
		TraceHash: "somehash",
		Signature: "somesig",
		Payload:   Payload{},
	}

	err := Verify(log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key hex")
}

func TestCanonicalJSON_CrossPlatformDeterminism(t *testing.T) {
	// This test ensures that the same payload always produces the same hash
	// regardless of how the struct fields are ordered in memory

	payload1 := Payload{
		EnvelopeXdr:   "envelope",
		ResultMetaXdr: "result",
		Events:        []string{"e1", "e2"},
		Logs:          []string{"l1"},
	}

	payload2 := Payload{
		Logs:          []string{"l1"},
		Events:        []string{"e1", "e2"},
		ResultMetaXdr: "result",
		EnvelopeXdr:   "envelope",
	}

	bytes1, err := marshalCanonical(payload1)
	require.NoError(t, err)

	bytes2, err := marshalCanonical(payload2)
	require.NoError(t, err)

	// Both should produce identical JSON
	assert.Equal(t, bytes1, bytes2)
}

func TestGenerate_DeterministicHash(t *testing.T) {
	// Generate the same audit log multiple times and verify hash consistency
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	hashes := make([]string, 5)
	for i := 0; i < 5; i++ {
		log, err := Generate(
			"test-tx-hash",
			"envelope-xdr",
			"result-meta-xdr",
			[]string{"event1", "event2"},
			[]string{"log1", "log2"},
			privateKeyHex,
		)
		require.NoError(t, err)
		hashes[i] = log.TraceHash
	}

	// All hashes should be identical (except timestamp won't affect payload hash)
	for i := 1; i < len(hashes); i++ {
		assert.Equal(t, hashes[0], hashes[i], "hash %d differs from first", i)
	}
}

func TestGenerate_EmptyArrays(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	// Test with empty arrays
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr",
		"result-meta-xdr",
		[]string{},
		[]string{},
		privateKeyHex,
	)

	require.NoError(t, err)
	assert.NotNil(t, log)

	// Verify should still work
	err = Verify(log)
	assert.NoError(t, err)
}

func TestGenerate_NilArrays(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privateKeyHex := hex.EncodeToString(privateKey)

	// Test with nil arrays
	log, err := Generate(
		"test-tx-hash",
		"envelope-xdr",
		"result-meta-xdr",
		nil,
		nil,
		privateKeyHex,
	)

	require.NoError(t, err)
	assert.NotNil(t, log)

	// Verify should still work
	err = Verify(log)
	assert.NoError(t, err)
}
