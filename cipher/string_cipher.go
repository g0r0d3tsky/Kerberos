package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func Encrypt(plainText string, passPhrase string) (string, error) {
	key := []byte(passPhrase)
	plainTextBytes := []byte(plainText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Генерация IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Шифрование
	stream := cipher.NewCTR(block, iv)
	cipherText := make([]byte, len(plainTextBytes))
	stream.XORKeyStream(cipherText, plainTextBytes)

	// Комбинирование IV и зашифрованного текста
	result := append(iv, cipherText...)

	return hex.EncodeToString(result), nil
}

func Decrypt(cipherText string, passPhrase string) (string, error) {
	key := []byte(passPhrase)
	cipherTextBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Извлечение IV
	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]

	// Расшифровка
	stream := cipher.NewCTR(block, iv)
	plainText := make([]byte, len(cipherTextBytes))
	stream.XORKeyStream(plainText, cipherTextBytes)

	return string(plainText), nil
}

func Generate128BitsOfRandomEntropy() ([]byte, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func CreateMD5(input string) string {
	hash := md5.New()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}
