# go-oae

[![Go Reference](https://pkg.go.dev/badge/github.com/mrknow-all/go-oae.svg)](https://pkg.go.dev/github.com/mrknow-all/go-oae)

go-oae implements online authenticated encryption as described in paper "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"
by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár (https://eprint.iacr.org/2015/189) in Go.

Online authenticated encryption allows encrypting the plaintext stream on the fly and later partially decrypting the
ciphertext stream. The ciphertext is authenticated, which means that modification, reordering, appending the data will
be detected.


## Installation

Install using `go get -u github.com/mrknow-all/go-oae`.

## Example

This is the basic example which encrypts file into to another file.
```Go
func EncryptFile(name string, encryptedName string, topSecretKey []byte) error {
    plaintext, err := os.Open("source.txt"))
    if err != nil {
        return err
    }
    defer plaintext.Close()
    ciphertext, err := os.Create("encrypted.dat"))
    if err != nil {
        return err
    }
    defer ciphertext.Close()
    writer, err := NewEncryptingWriterWithHeader(ciphertext, topSecretKey, nil, EncryptOptions{})
    if err != nil {
        return err
    }
    _, err = io.Copy(writer, plaintext)
    if err != nil {
        return err
    }
    err = writer.Close()
    if err != nil {
        return err
    }
    return nil
}

func DecryptFile(topSecretKey []byte) error {
    ciphertext, err := os.Open("encrypted.dat")
    if err != nil {
        return err
    }
    defer ciphertext.Close()
    plaintext, err := os.Create("decrypted.txt")
    if err != nil {
        return err
    }
    defer plaintext.Close()
    reader, err := NewDecryptingReaderWithHeader(plaintext, topSecretKey, nil)
    if err != nil {
        return err
    }
    _, err = io.Copy(plaintext, reader)
    if err != nil {
        return err
    }
    return nil
}
```

See [documentation](https://pkg.go.dev/github.com/mrknow-all/go-oae) for more examples and API documentation.

## License

This library is distributed under MIT license, see LICENSE.
