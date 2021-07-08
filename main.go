package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"log"

	//"crypto/ecdsa"
	"crypto/ed25519"
	//"crypto/elliptic"
	"crypto/sha1"
	//"crypto/sha256"
	"crypto/rand"
	"crypto/x509"
	//"encoding/hex"
	"encoding/pem"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"io/ioutil"
	"net"
	"os"
)
import "fmt"

var (
	PubKeyPrefix             = []byte{0x50, 0x55, 0x42, 0x4b, 0x45, 0x59, 0x52, 0x41, 0x57, 0x20}
	SignatureAndPubKeyPrefix = []byte{0x53, 0x49, 0x47, 0x4e, 0x41, 0x54, 0x55, 0x52, 0x45, 0x41, 0x4e, 0x44, 0x50, 0x55, 0x42, 0x4b, 0x45, 0x59, 0x20}
	SignatureCipherPrefix    = []byte{0x53, 0x49, 0x47, 0x4e, 0x41, 0x54, 0x55, 0x52, 0x45, 0x43, 0x49, 0x50, 0x48, 0x45, 0x52, 0x20}
	//PubKeyHashPrefix        = []byte{0x50, 0x55, 0x42, 0x4b, 0x45, 0x59, 0x48, 0x41, 0x53, 0x48, 0x20}
	MessagePrefix           = []byte{0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x4d, 0x53, 0x47, 0x20}
	StartPrefix             = []byte{0x53, 0x54, 0x41, 0x52, 0x54}
	tempPrivKey, tempPubKey [32]byte
	usernameEntered         = false
	personPubKey            []byte
	sharedKey               []byte
)

func GenerateKey_Ed25519() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	checkError(err)
	return pub, priv
}

func GenerateEphemeralKey() ([32]byte, [32]byte) {
	var pub, priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		os.Exit(1)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	log.Println("New Key")
	return pub, priv
}

/*
func GenerateEphemeralKey(priv, pub *[32]byte) {
	//var pub, priv [32]byte
	if _, err := io.ReadFull(rand.Reader, (*priv)[:]); err != nil {
		fmt.Println(err)
	}
	curve25519.ScalarBaseMult(*&pub, *&priv)
	fmt.Printf("%x %x", *priv, *pub)
}
*/
func main() {
	// Generate a long-term Ed25519 key used for signing and verifying ephemeral keys
	// Save the key encoded as PKCS8 for the PrivKey and PKIX for the PubKey
	// The PubKey will be sent to the party through the internet as a file
	// The checksum of the file will be verified over the phone to ensure authenticity

	privKey := importPEMKey("priv.pem")
	//pubKey := importPublicPEMKey("pub.pem")
	//pubKey, privKey := GenerateKey_Ed25519()
	//savePublicPEMKey("pub.pem", pubKey)
	//savePEMKey("priv.pem", privKey)

	// Generate a temporary ephemeral key (Curve25519)
	// The PubKey will be sent over the TCP server encoded as HEX
	//tempPubKey, tempPrivKey = GenerateEphemeralKey()
	//fmt.Println(tempPrivKey)

	//var aliceShared, bobShared [32]byte
	//curve25519.ScalarMult(&aliceShared, &alicePrivateKey, &bobPublicKey)
	//curve25519.ScalarMult(&bobShared, &bobPrivateKey, &alicePublicKey)

	// A signed SHA256 hash of the PubKey is sent, when received,
	// the other party compares hashes and then verifies the signature

	//AlicePubKeyHash := sha256.Sum256(alicePublicKey[:])
	//fmt.Printf("%x\n", hex.EncodeToString(apkH[:]))
	//fmt.Printf("\npublic key hash: %x\n", AlicePubKeyHash)

	//s1 := ed25519.Sign(alicePrivateKey0, alicePublicKey[:])
	//s1 := ed25519.Sign(alicePrivateKey0, AlicePubKeyHash[:])
	//yes := ed25519.Verify(alicePublicKey0, AlicePubKeyHash[:], s1)
	//fmt.Printf("signature %x %t\n", s1, yes)

	//hash := sha256.New
	//secret := []byte("lol")
	//salt := make([]byte, hash().Size())
	//if _, err := rand.Read(salt); err != nil {
	//	panic(err)
	//}
	//hkdf_ := hkdf.New(hash, aliceShared[:], salt, nil)
	//hkdfkey := make([]byte, 16)
	//if _, err := io.ReadFull(hkdf_, hkdfkey); err != nil {
	//	panic(err)
	//}
	//fmt.Printf("\n\nHKDF of Alice's shared secret %x\n", hkdfkey)
	//ciphertext := aesEncrypt([]byte("pula mea pulaaaaaaaaaaaaaaaaaaaaaaaaaaaa 00000000000000000000000000000000000000000000000000000 XX"), hkdfkey)
	//fmt.Printf("\n%x", ciphertext)
	//plaintext := aesDecrypt(ciphertext, hkdfkey)
	//fmt.Printf("\n%s", plaintext)
	//savePEMKey("priv.pem", alicePrivateKey0)
	//savePublicPEMKey("pub.pem", alicePublicKey0)
	//h := fileSHA1("pub.pem")
	//fmt.Printf("\n%X", h)
	//pv := importPEMKey("priv.pem")
	//fmt.Printf("\n%x %d", pv, len(pv))
	//fmt.Println(string(0x0A))

	//usernameEntered := false
	//var personPubKey []byte
	//var sharedKey []byte

	conn, err := net.Dial("tcp", "127.0.0.1:8778")
	checkError(err)
	defer conn.Close()
	go func() {
		for {
			reader := bufio.NewReader(os.Stdin)
			text, err := reader.ReadBytes('\n')
			checkError(err)
			if text[0] == 13 && text[1] == 10 {
				log.Println("Empty message")
			} else {
				msg := bytes.TrimSpace(text)
				if !usernameEntered {
					_, err := conn.Write(msg)
					if err != nil {
						if err == io.EOF {
							log.Println(io.EOF)
							break
						}
						log.Println(err)
						break
					}
					usernameEntered = true
				} else {
					/*
						hash := sha256.New
						salt := make([]byte, hash().Size())
						if _, err := rand.Read(salt); err != nil {
							os.Exit(1)
						}
						log.Printf("HkdfSalt: %x", salt)
						hkdf_ := hkdf.New(hash, sharedKey, salt, nil)
						hkdfkey := make([]byte, 16)
						if _, err := io.ReadFull(hkdf_, hkdfkey); err != nil {
							os.Exit(1)
						}
						log.Printf("HkdfKey: %x", hkdfkey)

						ciphertext := aesEncrypt(msg, hkdfkey)
						encrypted := append(MessagePrefix, ciphertext...)
						encrypted = append(encrypted, salt...)
						_, err := conn.Write(encrypted)
						if err != nil {
							if err == io.EOF {
								log.Println(err)
								break
							}
							log.Println(err)
							break
						}
						log.Println("Sent encrypted message")
					*/
					secret := generateHkdf(sharedKey)
					ciphertext := aesEncrypt(msg, secret)
					encrypted := append(MessagePrefix, ciphertext...)
					_, err := conn.Write(encrypted)
					if err != nil {
						if err == io.EOF {
							log.Println(err)
							break
						}
						log.Println(err)
						break
					}
				}
			}
		}
	}()
	for {
		msgc := make([]byte, 2048)
		n, err := conn.Read(msgc)
		if err != nil {
			if err == io.EOF {
				log.Println(err)
				break
			}
			log.Println(err)
			break
		}
		switch {
		case bytes.Contains(msgc[:n], StartPrefix):
			// Alice sends Bob her ephemeral public key
			tempPubKey, tempPrivKey = GenerateEphemeralKey()
			log.Printf("PubKey: %x Len: %d", tempPubKey[:], len(tempPubKey[:]))
			log.Println("Alice =====> Sent PubKey to Bob")
			w := append(PubKeyPrefix, tempPubKey[:]...)
			_, err = conn.Write(w)
			if err != nil {
				if err == io.EOF {
					log.Println(io.EOF)
					break
				}
				log.Println(err)
				break
			}
		case bytes.Contains(msgc[:n], PubKeyPrefix):
			// Bob received Alice's public key
			tempPubKey, tempPrivKey = GenerateEphemeralKey()
			log.Printf("PubKey: %x Len: %d", tempPubKey[:], len(tempPubKey[:]))
			log.Println("Bob =====> Received PubKey from Alice")
			t := msgc[:n]
			pubKeyExtract := t[len(PubKeyPrefix):]
			//copy(personPubKey, pubKeyExtract)
			personPubKey = pubKeyExtract
			log.Printf("Alice PubKey: %x Len: %d", pubKeyExtract, len(pubKeyExtract))

			var pubKeyRaw [32]byte
			copy(pubKeyRaw[:], pubKeyExtract)
			var shared [32]byte
			// Bob computes the shared secret
			curve25519.ScalarMult(&shared, &tempPrivKey, &pubKeyRaw)
			log.Printf("Shared: %x Len: %d", shared[:], len(shared[:]))
			sharedKey = shared[:]
			//copy(sharedKey, shared[:])

			// Bob: SB(SHA256(BK, AK))
			concatenatedPubKeys := append(tempPubKey[:], pubKeyExtract...)
			concatenatedPubKeysHash := sha256.Sum256(concatenatedPubKeys)
			//log.Printf("Concatenated PubKeys: %x Len: %d", concatenatedPubKeys, len(concatenatedPubKeys))
			log.Printf("Concatenated PubKeysHash: %x Len: %d", concatenatedPubKeysHash, len(concatenatedPubKeysHash))
			signature := ed25519.Sign(privKey, concatenatedPubKeysHash[:])
			log.Printf("Signature: %x Len: %d", signature, len(signature))
			// Bob: EK(SB(SHA256(BK, AK)))
			secret := generateHkdf(sharedKey)
			cipher := aesEncrypt(signature, secret)
			log.Printf("Ciphertext: %x Len: %d", cipher, len(cipher))
			final := append(tempPubKey[:], cipher...)

			temp := append(SignatureAndPubKeyPrefix, final...)
			_, err = conn.Write(temp)
			if err != nil {
				if err == io.EOF {
					fmt.Println(io.EOF)
					break
				}
				fmt.Println(err)
				break
			}
		case bytes.Contains(msgc[:n], SignatureAndPubKeyPrefix):
			// Alice
			log.Println("Alice =====> Received PubKey and Signature from Bob")
			t := msgc[:n]
			pubKeyExtract := t[len(SignatureAndPubKeyPrefix) : len(SignatureAndPubKeyPrefix)+32]
			cipherExtract := t[len(SignatureAndPubKeyPrefix)+32:]

			log.Printf("Bob PubKey: %x Len: %d", pubKeyExtract, len(pubKeyExtract))
			log.Printf("Ciphertext: %x Len: %d", cipherExtract, len(cipherExtract))

			var pubKeyRaw [32]byte
			copy(pubKeyRaw[:], pubKeyExtract)
			var shared [32]byte
			// Alice computes the shared key
			curve25519.ScalarMult(&shared, &tempPrivKey, &pubKeyRaw)
			//copy(sharedKey, shared[:])
			sharedKey = shared[:]

			log.Printf("Shared: %x Len: %d", shared[:], len(shared[:]))

			secret := generateHkdf(sharedKey)
			// Alice decrypts Bob's cipher using K
			signature := aesDecrypt(cipherExtract, secret)
			log.Printf("Signature: %x Len: %d", signature, len(signature))
			// Alice concatenates BK and AK then computes SHA256(BK, AK)
			verifyConcatenatedPubKeys := append(pubKeyExtract, tempPubKey[:]...)
			verifyConcatenatedPubKeysHash := sha256.Sum256(verifyConcatenatedPubKeys)
			//log.Printf("Concatenated PubKeys: %x Len: %d", verifyConcatenatedPubKeys, len(verifyConcatenatedPubKeys))
			log.Printf("Concatenated PubKeysHash: %x Len: %d", verifyConcatenatedPubKeysHash, len(verifyConcatenatedPubKeysHash))

			targetPubKey := importPublicPEMKey("target.pem")

			//verifySig := ed25519.Verify(targetPubKey, verifyConcatenatedPubKeys, signature)
			verifySig := ed25519.Verify(targetPubKey, verifyConcatenatedPubKeysHash[:], signature)
			log.Printf("Signature verified? %t", verifySig)
			if verifySig == false {
				os.Exit(1)
			}

			// Alice concatenates AK, BK and computes SHA256(AK, BK)
			concatenatedPubKeys := append(tempPubKey[:], pubKeyExtract...)
			concatenatedPubKeysHash := sha256.Sum256(concatenatedPubKeys)
			//log.Printf("Concatenated PubKeys: %x Len: %d", concatenatedPubKeys, len(concatenatedPubKeys))
			log.Printf("Concatenated PubKeysHash: %x Len: %d", concatenatedPubKeysHash, len(concatenatedPubKeysHash))
			//mySig := ed25519.Sign(privKey, concatenatedPubKeys)
			mySig := ed25519.Sign(privKey, concatenatedPubKeysHash[:])
			// Alice computes EK(SA(SHA256(AK, BK)))
			cipher := aesEncrypt(mySig, secret)
			temp := append(SignatureCipherPrefix, cipher...)
			_, err = conn.Write(temp)
			if err != nil {
				if err == io.EOF {
					fmt.Println(io.EOF)
					break
				}
				fmt.Println(err)
				break
			}
		case bytes.Contains(msgc[:n], SignatureCipherPrefix):
			// BOB
			log.Println("Bob =====> Received Cipher of Signature from Alice")
			t := msgc[:n]
			cipher := t[len(SignatureCipherPrefix):]
			secret := generateHkdf(sharedKey)
			signature := aesDecrypt(cipher, secret)
			verifyConcatenatedPubKeys := append(personPubKey, tempPubKey[:]...)
			verifyConcatenatedPubKeysHash := sha256.Sum256(verifyConcatenatedPubKeys)
			//log.Printf("Concatenated PubKeys: %x Len: %d", verifyConcatenatedPubKeys, len(verifyConcatenatedPubKeys))
			log.Printf("Concatenated PubKeysHash: %x Len: %d", verifyConcatenatedPubKeysHash, len(verifyConcatenatedPubKeysHash))
			targetPubKey := importPublicPEMKey("target.pem")
			verifySig := ed25519.Verify(targetPubKey, verifyConcatenatedPubKeysHash[:], signature)
			log.Printf("Signature verified: %t", verifySig)

			// START AGAIN
			/*
				tempPubKey, tempPrivKey = GenerateEphemeralKey()
				log.Printf("Client PubKey: %x", tempPubKey[:])
				w := append(PubKeyPrefix, tempPubKey[:]...)
				_, err = conn.Write(w)
				if err != nil {
					if err == io.EOF {
						log.Println(io.EOF)
						break
					}
					log.Println(err)
					break
				}
			*/
		case bytes.Contains(msgc[:n], MessagePrefix):
			t := msgc[:n]
			cipher := t[len(MessagePrefix):]
			secret := generateHkdf(sharedKey)
			plain := aesDecrypt(cipher, secret)
			log.Printf("Message: %s", plain)

			//w := append(PubKeyPrefix, tempPubKey[:]...)
			_, err = conn.Write(StartPrefix)
			if err != nil {
				if err == io.EOF {
					log.Println(io.EOF)
					break
				}
				log.Println(err)
				break
			}
		default:
			log.Printf("Server: %s", msgc[:n])
		}
		/*
			if bytes.Contains(msgc[:n], StartPrefix) {
				log.Println("Start Exchanging Keys")
				log.Printf("PubKey: %x", tempPubKey[:])

				tempPubKeyHex := make([]byte, hex.EncodedLen(len(tempPubKey)))
				hex.Encode(tempPubKeyHex, tempPubKey[:])

				w := append(PubKeyPrefix, tempPubKeyHex...)
				_, err = conn.Write(w)
				if err != nil {
					if err == io.EOF {
						log.Println(io.EOF)
						break
					}
					log.Println(err)
					break
				}
			} else if bytes.Contains(msgc[:n], PubKeyPrefix) {
				log.Println("PubKey from the other client received")
				pubKeyHexExtract := msgc[:n][len(msgc[:n])-64 : len(msgc[:n])]
				personPubKey = pubKeyHexExtract
				log.Printf("Other client PubKey: %s", personPubKey)
				decodedPubKey := make([]byte, hex.DecodedLen(len(pubKeyHexExtract)))
				hex.Decode(decodedPubKey, pubKeyHexExtract)

				var pubKeyRaw [32]byte
				copy(pubKeyRaw[:], decodedPubKey)
				var shared [32]byte

				curve25519.ScalarMult(&shared, &tempPrivKey, &pubKeyRaw)
				log.Printf("SharedKey: %s", hex.EncodeToString(shared[:]))
				sharedKey = shared[:]

				pubKeyHash := sha256.Sum256(tempPubKey[:])
				signature := ed25519.Sign(privKey, pubKeyHash[:])

				//log.Printf("Public Key Hash: %s", pubKeyHash)
				//log.Printf("Signature: %s", signature)
				//log.Println(len(pubKeyHash), len(signature))

				temp := append(pubKeyHash[:], signature...)
				dst := make([]byte, hex.EncodedLen(len(temp)))
				hex.Encode(dst, temp)
				temp2 := append(PubKeyHashPrefix, dst...)
				_, err = conn.Write(temp2)
				if err != nil {
					if err == io.EOF {
						fmt.Println(io.EOF)
						break
					}
					fmt.Println(err)
					break
				}
			} else if bytes.Contains(msgc[:n], PubKeyHashPrefix) {
				log.Println("PubKeyHash from the other client received")
				o2 := msgc[:n][len(msgc[:n])-128 : len(msgc[:n])]
				o3 := msgc[:n][len(msgc[:n])-192 : len(msgc[:n])-128]

				//log.Printf("Public Key Hash: %s", o3)
				//log.Printf("Signature: %s", o2)

				decodedHash := make([]byte, hex.DecodedLen(len(o3)))
				hex.Decode(decodedHash, o3)

				decodedSignature := make([]byte, hex.DecodedLen(len(o2)))
				hex.Decode(decodedSignature, o2)

				targetPubKey := importPublicPEMKey("target.pem")
				ok := ed25519.Verify(targetPubKey, decodedHash, decodedSignature)
				log.Printf("Signature verified? %t", ok)

				var t [32]byte
				lp1 := make([]byte, hex.DecodedLen(len(personPubKey)))
				hex.Decode(lp1, personPubKey)
				copy(t[:], lp1)

				//pubKeyHash := sha256.Sum256(personPubKey[:])
				pubKeyHash := sha256.Sum256(t[:])
				log.Printf("Other client PubKeyHash: %x", pubKeyHash)
				log.Printf("Hashes match? %t", bytes.Equal(pubKeyHash[:], decodedHash))
				//tempPubKey, tempPrivKey = GenerateEphemeralKey()
			} else if bytes.Contains(msgc[:n], MessagePrefix) {
				log.Println("Encrypted Message Received from other client")
				hash := sha256.New
				//secret := []byte("lol")
				salt := make([]byte, hash().Size())
				if _, err := rand.Read(salt); err != nil {
					log.Println(err)
					break
				}
				//hkdf_ := hkdf.New(hash, aliceShared[:], salt, nil)
				hkdf_ := hkdf.New(hash, sharedKey, nil, nil)
				hkdfkey := make([]byte, 16)
				if _, err := io.ReadFull(hkdf_, hkdfkey); err != nil {
					log.Println(err)
					break
				}
				log.Printf("HkdfKey: %x", hkdfkey)
				t1 := msgc[:n]
				idx := bytes.IndexByte(msgc[:n], 0x20)
				//plaintext := aesDecrypt(t1[idx+len(MessagePrefix)+1:], hkdfkey)
				plaintext := aesDecrypt(t1[idx+1:], hkdfkey)
				log.Printf("\n======= Server: %s\n", plaintext)

				tempPubKey, tempPrivKey = GenerateEphemeralKey()
				log.Printf("Client PubKey: %x", tempPubKey[:])
				tempPubKeyHex := make([]byte, hex.EncodedLen(len(tempPubKey)))
				hex.Encode(tempPubKeyHex, tempPubKey[:])

				w := append(PubKeyPrefix, tempPubKeyHex...)
				_, err = conn.Write(w)
				if err != nil {
					if err == io.EOF {
						log.Println(io.EOF)
						break
					}
					log.Println(err)
					break
				}
			} else {
				log.Printf("Server: %s", msgc[:n])
			}
		*/
	}
}
func savePEMKey(fileName string, key ed25519.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	checkError(err)
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	err = pem.Encode(outFile, privateKey)
	checkError(err)
}
func importPEMKey(fileName string) ed25519.PrivateKey {
	b, err := ioutil.ReadFile(fileName)
	checkError(err)
	block, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	checkError(err)
	return k.(ed25519.PrivateKey)
}
func savePublicPEMKey(fileName string, pubkey ed25519.PublicKey) {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	checkError(err)
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}
func importPublicPEMKey(fileName string) ed25519.PublicKey {
	b, err := ioutil.ReadFile(fileName)
	checkError(err)
	block, _ := pem.Decode(b)
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	checkError(err)
	return k.(ed25519.PublicKey)
}
func aesEncrypt(plaintext, key []byte) []byte {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		os.Exit(1)
	}
	block, err := aes.NewCipher(key)
	checkError(err)
	gcm, err := cipher.NewGCM(block)
	checkError(err)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}
func aesDecrypt(ciphertext, key []byte) []byte {
	block, err := aes.NewCipher(key)
	checkError(err)
	gcm, err := cipher.NewGCM(block)
	checkError(err)
	plaintext, err := gcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	checkError(err)
	return plaintext
}
func fileSHA1(file string) []byte {
	f, err := os.Open(file)
	checkError(err)
	defer f.Close()
	h := sha1.New()
	io.Copy(h, f)
	h2 := h.Sum(nil)
	return h2
}
func generateHkdf(data []byte) []byte {
	_hkdf := hkdf.New(sha256.New, data, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(_hkdf, key); err != nil {
		os.Exit(1)
	}
	return key
}
func checkError(err error) {
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
