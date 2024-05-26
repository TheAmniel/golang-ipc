package ipc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
)

func (sc *Server) keyExchange() ([32]byte, error) {
	var shared [32]byte

	priv, pub, err := generateKeys()
	if err != nil {
		return shared, err
	}

	// send servers public key
	err = sendPublic(sc.conn, pub)
	if err != nil {
		return shared, err
	}

	// received clients public key
	pubRecvd, err := recvPublic(sc.conn)
	if err != nil {
		return shared, err
	}

	data, err := priv.ECDH(pubRecvd)
	if err != nil {
		return shared, err
	}

	shared = sha256.Sum256(data)
	return shared, nil

}

func (cc *Client) keyExchange() ([32]byte, error) {

	var shared [32]byte

	priv, pub, err := generateKeys()
	if err != nil {
		return shared, err
	}

	// received servers public key
	pubRecvd, err := recvPublic(cc.conn)
	if err != nil {
		return shared, err
	}

	// send clients public key
	err = sendPublic(cc.conn, pub)
	if err != nil {
		return shared, err
	}

	data, err := priv.ECDH(pubRecvd)
	if err != nil {
		return shared, err
	}
	shared = sha256.Sum256(data)

	return shared, nil
}

func generateKeys() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priva, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	puba := priva.PublicKey()

	return priva, puba, err

}

func sendPublic(conn net.Conn, pub *ecdh.PublicKey) error {
	pubSend := pub.Bytes()
	if pubSend == nil {
		return errors.New("public key cannot be converted to bytes")
	}

	_, err := conn.Write(pubSend)
	if err != nil {
		return errors.New("could not sent public key")
	}

	return nil
}

func recvPublic(conn net.Conn) (*ecdh.PublicKey, error) {

	buff := make([]byte, 98)
	i, err := conn.Read(buff)
	if err != nil {
		return nil, errors.New("didn't received public key")
	}

	if i != 97 {
		return nil, errors.New("public key received isn't valid length")
	}

	recvdPub, err := bytesToPublicKey(buff[:i])

	if err != nil {
		return nil, err
	}

	return recvdPub, nil
}

func bytesToPublicKey(recvdPub []byte) (*ecdh.PublicKey, error) {
	if len(recvdPub) == 0 {
		return nil, errors.New("didn't received valid public key")
	}
	return ecdh.P384().NewPublicKey(recvdPub)
}

func createCipher(shared [32]byte) (*cipher.AEAD, error) {

	b, err := aes.NewCipher(shared[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	return &gcm, nil
}

func encrypt(g cipher.AEAD, data []byte) ([]byte, error) {

	nonce := make([]byte, g.NonceSize())

	_, err := io.ReadFull(rand.Reader, nonce)

	return g.Seal(nonce, nonce, data, nil), err

}

func decrypt(g cipher.AEAD, recdData []byte) ([]byte, error) {

	nonceSize := g.NonceSize()
	if len(recdData) < nonceSize {
		return nil, errors.New("not enough data to decrypt")
	}

	nonce, recdData := recdData[:nonceSize], recdData[nonceSize:]
	plain, err := g.Open(nil, nonce, recdData, nil)
	if err != nil {
		return nil, err
	}

	return plain, nil

}
