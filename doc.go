// Copyright 2022+ MrKnow-All. All rights reserved.
// License information can be found in the LICENSE file.

// Package oae implements online authenticated encryption as described in paper "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"
// by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár (https://eprint.iacr.org/2015/189)
//
// # Overview
//
// Online authenticated encryption allows encrypting the plaintext stream on the fly and later partially decrypting the
// ciphertext stream. The ciphertext is authenticated, which means that modification, reordering, appending the data
// will be detected.
//
// All types in this package implement standard Go interfaces: io.Reader, io.ReadSeeker and io.Writer. Note, that
// due to tamper-resistant properties of OAE you cannot rewrite or append parts of the ciphertext, only write the new
// ciphertext.
//
// All constructors accept key and aad parameters. Key must be securely stored in a separate secure storage, e.g. using
// AWS KMS (using envelope encryption), GCP Secret Manager or Hashicorp Vault. Aad is additional authenticated data,
// it is passed into HKDF function and may be nil. It is preferrable that user puts some kind of "tag" related
// to the plaintext in question.
//
// # Examples
//
// Encrypt a file into another file and decrypt it back.
//
//	func EncryptFile(topSecretKey []byte) error {
//	    plaintext, err := os.Open("source.txt")
//	    if err != nil {
//	        return err
//	    }
//	    defer plaintext.Close()
//	    ciphertext, err := os.Create("encrypted.dat")
//	    if err != nil {
//	        return err
//	    }
//	    defer ciphertext.Close()
//	    writer, err := oae.NewEncryptingWriterWithHeader(ciphertext, topSecretKey, nil, oae.EncryptOptions{})
//	    if err != nil {
//	        return err
//	    }
//	    _, err = io.Copy(writer, plaintext)
//	    if err != nil {
//	        return err
//	    }
//	    err = writer.Close()
//	    if err != nil {
//	        return err
//	    }
//	    return nil
//	}
//
//	func DecryptFile(topSecretKey []byte) error {
//	   ciphertext, err := os.Open("encrypted.dat")
//	   if err != nil {
//	       return err
//	   }
//	   defer ciphertext.Close()
//	   plaintext, err := os.Create("decrypted.txt")
//	   if err != nil {
//	       return err
//	   }
//	   defer plaintext.Close()
//	   reader, err := oae.NewDecryptingReaderWithHeader(plaintext, topSecretKey, nil)
//	   if err != nil {
//	       return err
//	   }
//	   _, err = io.Copy(plaintext, reader)
//	   if err != nil {
//	       return err
//	   }
//	   return nil
//	}
//
// Download and decrypt part of the encrypted blob from S3. Header and topSecretKey are stored separately. Note that
// this example requires passing the plaintextTotal.
//
//	func DownloadAndDecryptRange(header oae.CiphertextHeader, topSecretKey []byte, from, to, plaintextTotal int) ([]byte, error) {
//	    start, end := header.Algorithm.CiphertextRange(header.SegmentSize, int64(from), int64(to), int64(plaintextTotal))
//	    rangeHeader := fmt.Sprintf("bytes=%d-%d", start, end)
//	    var buf aws.WriteAtBuffer
//	    _, err := s3Downloader.Download(&buf, &s3.GetObject{
//	        Bucket: aws.String("bucket"),
//	        Key: aws.String("key"),
//	        Range: aws.String(rangeHeader),
//	    })
//	    if err != nil {
//	        return nil, err
//	    }
//	    ciphertext := bytes.NewReader(buf.Bytes())
//	    er, err := oae.NewDecryptingReader(ciphertext, topSecretKey, nil, header)
//	    if err != nil {
//	        return nil, err
//	    }
//	    var result bytes.Buffer
//	    _, err = io.Copy(&result, er)
//	    if err != nil {
//	        return nil, err
//	    }
//	    return result.Bytes(), nil
//	}
package oae
