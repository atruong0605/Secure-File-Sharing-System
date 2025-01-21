package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	EncryptionKey []byte
	HMACKey       []byte
	DSPrivateKey  userlib.DSSignKey
	PrivateKey    userlib.PrivateKeyType

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type fileAccess struct {
	Owner            bool
	AccessKey        []byte
	AccessHMACKey    []byte
	AccessUUID       uuid.UUID
	FileMetaDataUUID uuid.UUID
	FMDEncryptionKey []byte
	FMDHMACKey       []byte
	Children         map[string]Children
}

type Children struct {
	AccessUUID uuid.UUID
	AccessKey  []byte
	AccessHMAC []byte
}

type FileMetaData struct {
	Owner             string
	FileEncryptionKey []byte
	FileHMACKey       []byte
	FirstUUID         uuid.UUID
	LastUUID          uuid.UUID
}

type File struct {
	Content  []byte
	NextUUID uuid.UUID
}

type Access struct {
	FMDEncryptionKey []byte
	FMDHMACKey       []byte
	FileMetaDataUUID uuid.UUID
	Revoked          bool
}

type Invitation struct {
	AccessKey     []byte
	AccessHMACKey []byte
	AccessUUID    uuid.UUID
}

func slicesEqual(slice1, slice2 []byte) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var data []byte
	userdata.Username = username

	// Check for empty username
	if len(username) == 0 {
		return nil, errors.New("empty username not allowed")
	}

	// Create Public/Private key pairs
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(username+"publicKey", publicKey)
	userdata.PrivateKey = privateKey
	// Create Digital Signature public/private key pairs
	DSPrivateKey, DSPublicKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.DSPrivateKey = DSPrivateKey
	userlib.KeystoreSet(username+"DSKey", DSPublicKey)
	// Hash the password and create private keys
	salt := userlib.RandomBytes(32)
	passwordHash := userlib.Argon2Key([]byte(password), salt, 32)
	userdata.EncryptionKey = passwordHash[0:16]
	userdata.HMACKey = passwordHash[16:32]
	// Create UUID
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[0:16])
	if err != nil {
		return nil, err
	}

	// Check if user exists
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("user already exists")
	}

	// Serialize and Encrypt the data
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	IV := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(userdata.EncryptionKey, IV, userBytes)
	// Calculate the HMAC value
	HMACValue, err := userlib.HMACEval(userdata.HMACKey, ciphertext)
	if err != nil {
		return nil, err
	}

	// Append all of the bytes together and store in Datastore
	data = append(data, ciphertext...)
	data = append(data, HMACValue...)
	data = append(data, salt...)
	userlib.DatastoreSet(userUUID, data)

	// Return the User
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Calculate userUUID
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[0:16])
	if err != nil {
		return nil, err
	}

	// Get data from datastore
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("user does not exist")
	}
	if len(data) < 96 {
		return nil, errors.New("data has been tampered with")
	}

	// Separate Data
	ciphertext := data[0 : len(data)-96]
	HMACValue := data[len(data)-96 : (len(data)-96)+64]
	salt := data[len(data)-32:]

	// Calculate the PasswordHash and keys
	passwordHash := userlib.Argon2Key([]byte(password), salt, 32)
	EncryptionKey := passwordHash[0:16]
	HMACKey := passwordHash[16:32]

	// Check for tampering
	computedHMACValue, err := userlib.HMACEval(HMACKey, ciphertext)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(HMACValue, computedHMACValue) {
		return nil, errors.New("data has been tampered with or wrong password")
	}

	// Check for correct password
	userBytes := userlib.SymDec(EncryptionKey, ciphertext)
	err = json.Unmarshal(userBytes, userdataptr)
	if err != nil {
		return nil, err
	}
	if !slicesEqual(userdata.EncryptionKey, EncryptionKey) {
		return nil, errors.New("wrong password")
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var FileMetaData FileMetaData
	var fileAccess fileAccess
	var File File
	var Access Access
	if userdata == nil {
		return errors.New("user does not exist")
	}

	// Check if the fileAccess already exists
	namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
	if err != nil {
		return nil
	}
	fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
	if err != nil {
		return err
	}
	fileAccessData, ok := userlib.DatastoreGet(fileAccessUUID)
	if !ok {
		// If the file does not exist, create a new FileMetaData, fileAccess, and File struct
		// Create an Encryption and HMACKey for the FileMetaData
		FMDKeys, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename+userdata.Username+"FMD"))
		if err != nil {
			return err
		}
		FileMetaData.FileEncryptionKey = FMDKeys[0:16]
		FileMetaData.FileHMACKey = FMDKeys[16:32]

		// Create an Encryption and HMACKey for the fileAccess struct
		AKeys, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename+userdata.Username+"A"))
		if err != nil {
			return err
		}
		fileAccess.FMDEncryptionKey = AKeys[0:16]
		fileAccess.FMDHMACKey = AKeys[16:32]

		// Create UUIDs
		fileUUID := uuid.New()
		LastUUID := uuid.New()
		FileMetaDataUUID := uuid.New()

		// Store the data
		FileMetaData.Owner = userdata.Username
		FileMetaData.FirstUUID = fileUUID
		FileMetaData.LastUUID = LastUUID

		File.Content = content
		File.NextUUID = LastUUID

		fileAccess.FileMetaDataUUID = FileMetaDataUUID
		fileAccess.Owner = true
		fileAccess.Children = make(map[string]Children)

		// Serialize all the data
		fileAccessBytes, err := json.Marshal(fileAccess)
		if err != nil {
			return nil
		}
		FMDBytes, err := json.Marshal(FileMetaData)
		if err != nil {
			return err
		}
		fileBytes, err := json.Marshal(File)
		if err != nil {
			return err
		}

		// Encrypt all the data
		FAIV := userlib.RandomBytes(16)
		fileAccessCiphertext := userlib.SymEnc(userdata.EncryptionKey, FAIV, fileAccessBytes)
		FMDIV := userlib.RandomBytes(16)
		FMDCiphertext := userlib.SymEnc(fileAccess.FMDEncryptionKey, FMDIV, FMDBytes)
		fileIV := userlib.RandomBytes(16)
		fileCiphertext := userlib.SymEnc(FileMetaData.FileEncryptionKey, fileIV, fileBytes)

		// HMACValue checks for tampering
		fileAccessHMAC, err := userlib.HMACEval(userdata.HMACKey, fileAccessCiphertext)
		if err != nil {
			return err
		}
		FileMetaDataHMAC, err := userlib.HMACEval(fileAccess.FMDHMACKey, FMDCiphertext)
		if err != nil {
			return err
		}
		fileHMAC, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
		if err != nil {
			return err
		}

		FAData := append(fileAccessCiphertext, fileAccessHMAC...)
		FMDData := append(FMDCiphertext, FileMetaDataHMAC...)
		FData := append(fileCiphertext, fileHMAC...)

		// Store all the data
		userlib.DatastoreSet(fileAccessUUID, FAData)
		userlib.DatastoreSet(FileMetaDataUUID, FMDData)
		userlib.DatastoreSet(fileUUID, FData)

	} else {

		// Get the fileAccessData, then check for tampering and decrypt
		if len(fileAccessData) < 64 {
			return errors.New("data has been tampered with")
		}
		FACiphertext := fileAccessData[:len(fileAccessData)-64]
		FAHMACValue := fileAccessData[len(fileAccessData)-64:]
		computedFAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
		if err != nil {
			return nil
		}
		if !userlib.HMACEqual(FAHMACValue, computedFAHMACValue) {
			return errors.New("data has been tampered with")
		}
		FABytes := userlib.SymDec(userdata.EncryptionKey, FACiphertext)
		err = json.Unmarshal(FABytes, &fileAccess)
		if err != nil {
			return err
		}

		// If the file does exist, check if the user is the owner
		if fileAccess.Owner {
			// If the user is the owner of the file, use fileAccess to store the file

			// Get FileMetaData and check for tampering
			FileMetaDataUUID := fileAccess.FileMetaDataUUID
			FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
			if !ok {
				return errors.New("uuid has been tampered with")
			}
			if len(FMDData) < 64 {
				return errors.New("data has been tampered with")
			}

			FMDCiphertext := FMDData[:len(FMDData)-64]
			FMDHMACValue := FMDData[len(FMDData)-64:]

			// Check for tampering then decrypt
			computedFMDHMACValue, err := userlib.HMACEval(fileAccess.FMDHMACKey, FMDCiphertext)
			if err != nil {
				return err
			}
			if !userlib.HMACEqual(FMDHMACValue, computedFMDHMACValue) {
				return errors.New("data has been tampered with")
			}
			FMDBytes := userlib.SymDec(fileAccess.FMDEncryptionKey, FMDCiphertext)
			err = json.Unmarshal(FMDBytes, &FileMetaData)
			if err != nil {
				return err
			}
			// Create a new UUID for the file
			fileUUID := FileMetaData.FirstUUID

			// Store the data
			File.Content = content
			File.NextUUID = FileMetaData.LastUUID

			// Encrypt and serialize and store in the Datastore
			updatedFMDBytes, err := json.Marshal(FileMetaData)
			if err != nil {
				return err
			}
			fileBytes, err := json.Marshal(File)
			if err != nil {
				return err
			}

			FMDIV := userlib.RandomBytes(16)
			updatedFMDCiphertext := userlib.SymEnc(fileAccess.FMDEncryptionKey, FMDIV, updatedFMDBytes)
			fileIV := userlib.RandomBytes(16)
			fileCiphertext := userlib.SymEnc(FileMetaData.FileEncryptionKey, fileIV, fileBytes)

			FileMetaDataHMAC, err := userlib.HMACEval(fileAccess.FMDHMACKey, updatedFMDCiphertext)
			if err != nil {
				return err
			}
			fileHMAC, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
			if err != nil {
				return err
			}

			updatedFMDData := append(updatedFMDCiphertext, FileMetaDataHMAC...)
			FileData := append(fileCiphertext, fileHMAC...)

			// Store all the data
			userlib.DatastoreSet(FileMetaDataUUID, updatedFMDData)
			userlib.DatastoreSet(fileUUID, FileData)

		} else {
			// If the user is not the owner, use Access to store the file
			// Get the Access data from the datastore and check for tampering
			AccessUUID := fileAccess.AccessUUID
			AccessData, ok := userlib.DatastoreGet(AccessUUID)
			if !ok {
				return errors.New("user does not have access to this file")
			}
			if len(AccessData) < 64 {
				return errors.New("data has been tampered with")
			}
			AccessCiphertext := AccessData[:len(AccessData)-64]
			AccessHMACValue := AccessData[len(AccessData)-64:]

			computedAccessHMACValue, err := userlib.HMACEval(fileAccess.AccessHMACKey, AccessCiphertext)
			if err != nil {
				return err
			}
			if !userlib.HMACEqual(AccessHMACValue, computedAccessHMACValue) {
				return errors.New("data has been tampered with")
			}

			// Decrypt the Access data
			AccessBytes := userlib.SymDec(fileAccess.AccessKey, AccessCiphertext)
			err = json.Unmarshal(AccessBytes, &Access)
			if err != nil {
				return err
			}

			// Get the FileMetaData information
			FileMetaDataUUID := Access.FileMetaDataUUID
			FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
			if !ok {
				return errors.New("data has been tampered with")
			}
			if len(FMDData) < 64 {
				return errors.New("data has been tampered with")
			}
			FMDCiphertext := FMDData[:len(FMDData)-64]
			FMDHMACValue := FMDData[len(FMDData)-64:]

			// Check for tampering and decrypt and deserialize
			computedFMDHMACValue, err := userlib.HMACEval(Access.FMDHMACKey, FMDCiphertext)
			if err != nil {
				return nil
			}
			if !userlib.HMACEqual(FMDHMACValue, computedFMDHMACValue) {
				return errors.New("data has been tampered with")
			}
			FMDBytes := userlib.SymDec(Access.FMDEncryptionKey, FMDCiphertext)
			err = json.Unmarshal(FMDBytes, &FileMetaData)
			if err != nil {
				return err
			}

			// Create a new UUID for the file
			fileUUID := FileMetaData.FirstUUID

			// Store the data
			File.Content = content
			File.NextUUID = FileMetaData.LastUUID

			// Encrypt and serialize
			updatedFMDBytes, err := json.Marshal(FileMetaData)
			if err != nil {
				return err
			}
			fileBytes, err := json.Marshal(File)
			if err != nil {
				return err
			}
			FMDIV := userlib.RandomBytes(16)
			updatedFMDCiphertext := userlib.SymEnc(Access.FMDEncryptionKey, FMDIV, updatedFMDBytes)
			fileIV := userlib.RandomBytes(16)
			fileCiphertext := userlib.SymEnc(FileMetaData.FileEncryptionKey, fileIV, fileBytes)

			// Create HMAC values and append and store in Datastore
			updatedFMDHMACValue, err := userlib.HMACEval(Access.FMDHMACKey, updatedFMDCiphertext)
			if err != nil {
				return err
			}
			fileHMACValue, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
			if err != nil {
				return err
			}
			updatedFMDData := append(updatedFMDCiphertext, updatedFMDHMACValue...)
			fileData := append(fileCiphertext, fileHMACValue...)

			userlib.DatastoreSet(FileMetaDataUUID, updatedFMDData)
			userlib.DatastoreSet(fileUUID, fileData)

		}

	}

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var FileMetaData FileMetaData
	var Access Access
	var fileAccess fileAccess
	if userdata == nil {
		return errors.New("user does not exist")
	}

	// Check if the fileAccess already exists
	namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
	if err != nil {
		return err
	}
	fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
	if err != nil {
		return err
	}
	fileAccessData, ok := userlib.DatastoreGet(fileAccessUUID)
	if !ok {
		return errors.New("file does not exist")
	}
	if len(fileAccessData) < 64 {
		return errors.New("data has been tampered with")
	}
	FACiphertext := fileAccessData[:len(fileAccessData)-64]
	FAHMACValue := fileAccessData[len(fileAccessData)-64:]
	computedFAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(FAHMACValue, computedFAHMACValue) {
		return errors.New("data has been tampered with")
	}
	FABytes := userlib.SymDec(userdata.EncryptionKey, FACiphertext)
	err = json.Unmarshal(FABytes, &fileAccess)
	if err != nil {
		return err
	}

	if fileAccess.Owner {
		FileMetaDataUUID := fileAccess.FileMetaDataUUID
		FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
		if !ok {
			return errors.New("file does not exist")
		}
		if len(FMDData) < 64 {
			return errors.New("data has been tampered with")
		}
		FMDCiphertext := FMDData[:len(FMDData)-64]
		FMDHMACValue := FMDData[len(FMDData)-64:]

		// Check for tampering then decrypt
		computedFMDHMACValue, err := userlib.HMACEval(fileAccess.FMDHMACKey, FMDCiphertext)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(FMDHMACValue, computedFMDHMACValue) {
			return errors.New("data has been tampered with")
		}
		FMDBytes := userlib.SymDec(fileAccess.FMDEncryptionKey, FMDCiphertext)
		err = json.Unmarshal(FMDBytes, &FileMetaData)
		if err != nil {
			return err
		}

		// Create a new UUID
		newUUID := uuid.New()

		// Create a new file
		newFile := File{
			Content:  content,
			NextUUID: newUUID,
		}

		// Serialize and encrypt the new file content and store in Datastore
		fileBytes, err := json.Marshal(newFile)
		if err != nil {
			return err
		}
		fileIV := userlib.RandomBytes(16)
		fileCiphertext := userlib.SymEnc(FileMetaData.FileEncryptionKey, fileIV, fileBytes)
		fileHMACValue, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
		if err != nil {
			return err
		}
		fileData := append(fileCiphertext, fileHMACValue...)
		userlib.DatastoreSet(FileMetaData.LastUUID, fileData)

		FileMetaData.LastUUID = newUUID

		// Serialize and encrypt the updated FileMetaData
		updatedFMDBytes, err := json.Marshal(FileMetaData)
		if err != nil {
			return err
		}
		FMDIV := userlib.RandomBytes(16)
		updatedFMDCiphertext := userlib.SymEnc(fileAccess.FMDEncryptionKey, FMDIV, updatedFMDBytes)
		FileMetaDataHMAC, err := userlib.HMACEval(fileAccess.FMDHMACKey, updatedFMDCiphertext)
		if err != nil {
			return err
		}
		// Store the updated FileMetaData in the Datastore
		updatedFMDData := append(updatedFMDCiphertext, FileMetaDataHMAC...)
		userlib.DatastoreSet(FileMetaDataUUID, updatedFMDData)
	} else {
		// If the user is not the owner, then use AccessKeys to get the data
		AccessUUID := fileAccess.AccessUUID
		AccessData, ok := userlib.DatastoreGet(AccessUUID)
		if !ok {
			return errors.New("file does not exist")
		}
		if len(AccessData) < 64 {
			return errors.New("data has been tampered with")
		}
		AccessCiphertext := AccessData[:len(AccessData)-64]
		AccessHMACValue := AccessData[len(AccessData)-64:]

		// Check for tampering then decrypt
		computedAccessHMACValue, err := userlib.HMACEval(fileAccess.AccessHMACKey, AccessCiphertext)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(AccessHMACValue, computedAccessHMACValue) {
			return errors.New("data has been tampered with")
		}

		AccessBytes := userlib.SymDec(fileAccess.AccessKey, AccessCiphertext)
		err = json.Unmarshal(AccessBytes, &Access)
		if err != nil {
			return err
		}

		// Check if Access has been revoked
		if Access.Revoked {
			return errors.New("access has been revoked")
		}

		// Get FileMetaData and add the extra node to the LinkedList
		FileMetaDataUUID := Access.FileMetaDataUUID
		FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
		if !ok {
			return errors.New("file does not exist")
		}
		if len(FMDData) < 64 {
			return errors.New("data has been tampered with")
		}
		FMDCiphertext := FMDData[:len(FMDData)-64]
		FMDHMACValue := FMDData[len(FMDData)-64:]

		// Check for tampering then decrypt
		computedFMDHMACValue, err := userlib.HMACEval(Access.FMDHMACKey, FMDCiphertext)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(computedFMDHMACValue, FMDHMACValue) {
			return errors.New("data has been tampered with")
		}
		FMDBytes := userlib.SymDec(Access.FMDEncryptionKey, FMDCiphertext)
		err = json.Unmarshal(FMDBytes, &FileMetaData)
		if err != nil {
			return err
		}

		// Create a new UUID
		newUUID := uuid.New()

		// Create a new file
		newFile := File{
			Content:  content,
			NextUUID: newUUID,
		}

		// Serialize and encrypt the new file content and store in Datastore
		fileBytes, err := json.Marshal(newFile)
		if err != nil {
			return err
		}
		fileIV := userlib.RandomBytes(16)
		fileCiphertext := userlib.SymEnc(FileMetaData.FileEncryptionKey, fileIV, fileBytes)
		fileHMAC, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
		if err != nil {
			return err
		}
		FileData := append(fileCiphertext, fileHMAC...)
		userlib.DatastoreSet(FileMetaData.LastUUID, FileData)

		FileMetaData.LastUUID = newUUID

		// Serialize and encrypt the updateFMD and store in Datastore
		updatedFMDBytes, err := json.Marshal(FileMetaData)
		if err != nil {
			return err
		}
		FMDIV := userlib.RandomBytes(16)
		updatedFMDCiphertext := userlib.SymEnc(Access.FMDEncryptionKey, FMDIV, updatedFMDBytes)
		updatedFMDHMACValue, err := userlib.HMACEval(Access.FMDHMACKey, updatedFMDCiphertext)
		if err != nil {
			return err
		}
		updatedFMDData := append(updatedFMDCiphertext, updatedFMDHMACValue...)
		userlib.DatastoreSet(FileMetaDataUUID, updatedFMDData)

	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var FileMetaData FileMetaData
	var file File
	var Access Access
	var fileAccess fileAccess
	if userdata == nil {
		return nil, errors.New("user does not exist")
	}

	// Check if the fileAccess exists in the user's namespace
	namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
	if err != nil {
		return nil, err
	}
	fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
	if err != nil {
		return nil, err
	}
	fileAccessData, ok := userlib.DatastoreGet(fileAccessUUID)
	if !ok {
		return nil, errors.New("file does not exist")
	}
	if len(fileAccessData) < 64 {
		return nil, errors.New("data has been tampered with")
	}
	FACiphertext := fileAccessData[:len(fileAccessData)-64]
	FAHMACValue := fileAccessData[len(fileAccessData)-64:]
	computedFAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(FAHMACValue, computedFAHMACValue) {
		return nil, errors.New("data has been tampered with")
	}
	FABytes := userlib.SymDec(userdata.EncryptionKey, FACiphertext)
	err = json.Unmarshal(FABytes, &fileAccess)
	if err != nil {
		return nil, err
	}

	if fileAccess.Owner {
		// If the user is the owner of the file, then use FMDKeys to get the data
		FileMetaDataUUID := fileAccess.FileMetaDataUUID
		FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
		if !ok {
			return nil, errors.New("file does not exist")
		}
		if len(FMDData) < 64 {
			return nil, errors.New("data has been tampered with")
		}
		FMDCiphertext := FMDData[:len(FMDData)-64]
		FMDHMACValue := FMDData[len(FMDData)-64:]

		// Check for tampering then decrypt
		computedFMDHMACValue, err := userlib.HMACEval(fileAccess.FMDHMACKey, FMDCiphertext)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(FMDHMACValue, computedFMDHMACValue) {
			return nil, errors.New("data has been tampered with")
		}
		FMDBytes := userlib.SymDec(fileAccess.FMDEncryptionKey, FMDCiphertext)
		err = json.Unmarshal(FMDBytes, &FileMetaData)
		if err != nil {
			return nil, err
		}

		// Check for tampering in the files, then decrypt the data and append to content
		currentUUID := FileMetaData.FirstUUID
		for currentUUID != FileMetaData.LastUUID {
			fileData, ok := userlib.DatastoreGet(currentUUID)
			if !ok {
				return nil, errors.New("file does not exist")
			}
			if len(fileData) < 64 {
				return nil, errors.New("data has been tampered with")
			}
			fileCiphertext := fileData[:len(fileData)-64]
			fileHMACValue := fileData[len(fileData)-64:]
			computedFileHMACValue, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
			if err != nil {
				return nil, err
			}
			if !userlib.HMACEqual(fileHMACValue, computedFileHMACValue) {
				return nil, errors.New("file has been tampered with")
			}
			fileBytes := userlib.SymDec(FileMetaData.FileEncryptionKey, fileCiphertext)
			err = json.Unmarshal(fileBytes, &file)
			if err != nil {
				return nil, err
			}
			content = append(content, file.Content...)
			currentUUID = file.NextUUID
		}

	} else {
		// If the user is not the owner, then use AccessKeys to get data
		AccessUUID := fileAccess.AccessUUID
		AccessData, ok := userlib.DatastoreGet(AccessUUID)
		if !ok {
			return nil, errors.New("file does not exist")
		}
		if len(AccessData) < 64 {
			return nil, errors.New("data has been tampered with")
		}
		AccessCiphertext := AccessData[:len(AccessData)-64]
		AccessHMACValue := AccessData[len(AccessData)-64:]

		// Check for tampering then decrypt
		computedAccessHMACValue, err := userlib.HMACEval(fileAccess.AccessHMACKey, AccessCiphertext)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(AccessHMACValue, computedAccessHMACValue) {
			return nil, errors.New("data has been tampered with")
		}
		AccessBytes := userlib.SymDec(fileAccess.AccessKey, AccessCiphertext)
		err = json.Unmarshal(AccessBytes, &Access)
		if err != nil {
			return nil, err
		}

		// Check if Access has been revoked
		if Access.Revoked {
			return nil, errors.New("access has been revoked")
		}

		// Get FileMetaData and load the file
		FileMetaDataUUID := Access.FileMetaDataUUID
		FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
		if !ok {
			return nil, errors.New("file does not exist")
		}
		if len(FMDData) < 64 {
			return nil, errors.New("data has been tampered with")
		}
		FMDCiphertext := FMDData[:len(FMDData)-64]
		FMDHMACValue := FMDData[len(FMDData)-64:]

		// Check for tampering and decrypt
		computedFMDHMACValue, err := userlib.HMACEval(Access.FMDHMACKey, FMDCiphertext)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(FMDHMACValue, computedFMDHMACValue) {
			return nil, errors.New("data has been tampered with")
		}
		FMDBytes := userlib.SymDec(Access.FMDEncryptionKey, FMDCiphertext)
		err = json.Unmarshal(FMDBytes, &FileMetaData)
		if err != nil {
			return nil, err
		}

		// Check for tampering in the files, then decrypt the data and append to content
		currentUUID := FileMetaData.FirstUUID
		for currentUUID != FileMetaData.LastUUID {
			fileData, ok := userlib.DatastoreGet(currentUUID)
			if !ok {
				return nil, errors.New("file does not exist")
			}
			if len(fileData) < 64 {
				return nil, errors.New("data has been tampered with")
			}
			fileCiphertext := fileData[:len(fileData)-64]
			fileHMACValue := fileData[len(fileData)-64:]
			computedFileHMACValue, err := userlib.HMACEval(FileMetaData.FileHMACKey, fileCiphertext)
			if err != nil {
				return nil, err
			}
			if !userlib.HMACEqual(fileHMACValue, computedFileHMACValue) {
				return nil, errors.New("file has been tampered with")
			}
			fileBytes := userlib.SymDec(FileMetaData.FileEncryptionKey, fileCiphertext)
			err = json.Unmarshal(fileBytes, &file)
			if err != nil {
				return nil, err
			}
			content = append(content, file.Content...)
			currentUUID = file.NextUUID
		}

	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	var Access Access
	var fileAccess fileAccess
	var invite Invitation
	var child Children
	if userdata == nil {
		return uuid.Nil, errors.New("user does not exist")
	}
	// Check if the fileAccess exists in the user's namespace
	namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
	if err != nil {
		return uuid.Nil, err
	}
	fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
	if err != nil {
		return uuid.Nil, err
	}
	fileAccessData, ok := userlib.DatastoreGet(fileAccessUUID)
	if !ok {
		return uuid.Nil, errors.New("file does not exist")
	}
	if len(fileAccessData) < 64 {
		return uuid.Nil, errors.New("data has been tampered with")
	}
	FACiphertext := fileAccessData[:len(fileAccessData)-64]
	FAHMACValue := fileAccessData[len(fileAccessData)-64:]
	computedFAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
	if err != nil {
		return uuid.Nil, err
	}
	if !userlib.HMACEqual(FAHMACValue, computedFAHMACValue) {
		return uuid.Nil, errors.New("data has been tampered with")
	}
	FABytes := userlib.SymDec(userdata.EncryptionKey, FACiphertext)
	err = json.Unmarshal(FABytes, &fileAccess)
	if err != nil {
		return uuid.Nil, err
	}
	if fileAccess.Owner {
		// If the user is the owner of the file, then create an invitation and access struct for the recipientUser
		// Create UUID and keys for the Access and invitation struct
		invitationUUID := uuid.New()
		accessUUID := uuid.New()
		AccessKeys, err := userlib.HashKDF(userdata.EncryptionKey, []byte("access"+recipientUsername))
		if err != nil {
			return uuid.Nil, err
		}
		AccessEncryption := AccessKeys[0:16]
		AccessHMAC := AccessKeys[16:32]

		// Store the data
		invite.AccessKey = AccessEncryption
		invite.AccessHMACKey = AccessHMAC
		invite.AccessUUID = accessUUID

		Access.FMDEncryptionKey = fileAccess.FMDEncryptionKey
		Access.FMDHMACKey = fileAccess.FMDHMACKey
		Access.FileMetaDataUUID = fileAccess.FileMetaDataUUID
		Access.Revoked = false

		child.AccessUUID = accessUUID
		child.AccessKey = AccessEncryption
		child.AccessHMAC = AccessHMAC
		fileAccess.Children[recipientUsername] = child

		// Serialize the data
		inviteBytes, err := json.Marshal(invite)
		if err != nil {
			return uuid.Nil, err
		}
		accessBytes, err := json.Marshal(Access)
		if err != nil {
			return uuid.Nil, err
		}
		FABytes, err := json.Marshal(fileAccess)
		if err != nil {
			return uuid.Nil, err
		}

		// Encrypt the invitation data using hybrid encryption and put a digital signature on it then store
		encryptedPrivateKey, inviteCiphertext, err := hybridEncryption(recipientUsername, inviteBytes)
		if err != nil {
			return uuid.Nil, err
		}

		inviteCiphertext = append(inviteCiphertext, encryptedPrivateKey...)
		DSign, err := userlib.DSSign(userdata.DSPrivateKey, inviteCiphertext)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(invitationUUID, append(inviteCiphertext, DSign...))

		// Store the rest of the data
		FAIV := userlib.RandomBytes(16)
		FACiphertext := userlib.SymEnc(userdata.EncryptionKey, FAIV, FABytes)
		FAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(fileAccessUUID, append(FACiphertext, FAHMACValue...))

		AccessIV := userlib.RandomBytes(16)
		AccessCiphertext := userlib.SymEnc(AccessEncryption, AccessIV, accessBytes)
		AccessHMACValue, err := userlib.HMACEval(AccessHMAC, AccessCiphertext)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(accessUUID, append(AccessCiphertext, AccessHMACValue...))

		return invitationUUID, nil

	} else {
		// If the user is not the owner of the file, then create an invitation using the access struct for the recipientUser
		invitationUUID := uuid.New()
		// Use user's Access struct to create a new invitation struct
		invite.AccessUUID = fileAccess.AccessUUID
		invite.AccessKey = fileAccess.AccessKey
		invite.AccessHMACKey = fileAccess.AccessHMACKey

		// Serialize the data
		inviteBytes, err := json.Marshal(invite)
		if err != nil {
			return uuid.Nil, err
		}
		// Encrypt the invitation data using hybrid encryption and put a digital signature on it then store
		encryptedPrivateKey, inviteCiphertext, err := hybridEncryption(recipientUsername, inviteBytes)
		if err != nil {
			return uuid.Nil, err
		}
		inviteCiphertext = append(inviteCiphertext, encryptedPrivateKey...)
		DSign, err := userlib.DSSign(userdata.DSPrivateKey, inviteCiphertext)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(invitationUUID, append(inviteCiphertext, DSign...))

		return invitationUUID, nil

	}

}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	var Access Access
	var fileAccess fileAccess
	var invite Invitation
	if userdata == nil {
		return errors.New("user does not exist")
	}
	// Check if the fileAccess exists in the user's namespace
	namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
	if err != nil {
		return err
	}
	fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(fileAccessUUID)
	if ok {
		return errors.New("files cannot have the same name")
	} else {
		// Get the invitation struct
		invitationUUID := invitationPtr
		invitationData, ok := userlib.DatastoreGet(invitationUUID)
		if !ok {
			return errors.New("invitation does not exist")
		}
		if len(invitationData) < 512 {
			return errors.New("data has been tampered with")
		}
		ciphertext := invitationData[:len(invitationData)-512]
		symKeyBytes := invitationData[len(ciphertext) : len(invitationData)-256]
		sig := invitationData[len(invitationData)-256:]
		invitationBytes, err := hybridDecryption(senderUsername, userdata.PrivateKey, ciphertext, sig, symKeyBytes)
		if err != nil {
			return nil
		}
		err = json.Unmarshal(invitationBytes, &invite)
		if err != nil {
			return err
		}
		// Get the Access struct
		AccessUUID := invite.AccessUUID
		AccessKey := invite.AccessKey
		AccessHMACKey := invite.AccessHMACKey

		AccessData, ok := userlib.DatastoreGet(AccessUUID)
		if !ok {
			return errors.New("access does not exist")
		}
		if len(AccessData) < 64 {
			return errors.New("data has been tampered with")
		}
		accessCiphertext := AccessData[:len(AccessData)-64]
		AccessHMACValue := AccessData[len(AccessData)-64:]
		computedAccessHMACValue, err := userlib.HMACEval(AccessHMACKey, accessCiphertext)
		if err != nil {
			return nil
		}
		if !userlib.HMACEqual(AccessHMACValue, computedAccessHMACValue) {
			return errors.New("data has been tampered with")
		}
		AccessBytes := userlib.SymDec(AccessKey, accessCiphertext)
		err = json.Unmarshal(AccessBytes, &Access)
		if err != nil {
			return err
		}
		if Access.Revoked {
			return errors.New("access has been revoked")
		}
		// Create a new fileAccess object with the information from Access and Invitation
		namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
		if err != nil {
			return err
		}
		fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
		if err != nil {
			return err
		}
		fileAccess.AccessKey = AccessKey
		fileAccess.AccessHMACKey = AccessHMACKey
		fileAccess.AccessUUID = AccessUUID

		// Store the data on the Datastore
		FABytes, err := json.Marshal(fileAccess)
		if err != nil {
			return err
		}
		FAIV := userlib.RandomBytes(16)
		FACiphertext := userlib.SymEnc(userdata.EncryptionKey, FAIV, FABytes)
		FAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
		if err != nil {
			return err
		}
		FAData := append(FACiphertext, FAHMACValue...)
		userlib.DatastoreSet(fileAccessUUID, FAData)
		return nil
	}
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	var Access Access
	var fileAccess fileAccess
	var fileMetaData FileMetaData
	var file File
	if userdata == nil {
		return errors.New("user does not exist")
	}
	// Get the owner's fileAccess
	namespaceKey, err := userlib.HashKDF(userdata.EncryptionKey, []byte(filename))
	if err != nil {
		return err
	}
	fileAccessUUID, err := uuid.FromBytes(namespaceKey[0:16])
	if err != nil {
		return err
	}
	fileAccessData, ok := userlib.DatastoreGet(fileAccessUUID)
	if !ok {
		return errors.New("file does not exist")
	}
	if len(fileAccessData) < 64 {
		return errors.New("data has been tampered with")
	}
	FACiphertext := fileAccessData[:len(fileAccessData)-64]
	FAHMACValue := fileAccessData[len(fileAccessData)-64:]
	computedFAHMACValue, err := userlib.HMACEval(userdata.HMACKey, FACiphertext)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(FAHMACValue, computedFAHMACValue) {
		return errors.New("data has been tampered with")
	}
	FABytes := userlib.SymDec(userdata.EncryptionKey, FACiphertext)
	err = json.Unmarshal(FABytes, &fileAccess)
	if err != nil {
		return err
	}
	// Get the recipientUser's Access struct and set Revoked = True
	childData := fileAccess.Children[recipientUsername]
	revokedAccessUUID := childData.AccessUUID
	revokedEncryptionKey := childData.AccessKey
	revokedHMACKey := childData.AccessHMAC
	revokedAccessData, ok := userlib.DatastoreGet(revokedAccessUUID)
	if !ok {
		return errors.New("file does not exist")
	}
	if len(revokedAccessData) < 64 {
		return errors.New("data has been tampered with")
	}
	revokedAccessCiphertext := revokedAccessData[:len(revokedAccessData)-64]
	revokedAccessHMAC := revokedAccessData[len(revokedAccessData)-64:]
	computedRevokedHMACValue, err := userlib.HMACEval(revokedHMACKey, revokedAccessCiphertext)
	if err != nil {
		return nil
	}
	if !userlib.HMACEqual(revokedAccessHMAC, computedRevokedHMACValue) {
		return errors.New("data has been tampered with")
	}
	revokedBytes := userlib.SymDec(revokedEncryptionKey, revokedAccessCiphertext)
	err = json.Unmarshal(revokedBytes, &Access)
	if err != nil {
		return err
	}
	Access.Revoked = true
	delete(fileAccess.Children, recipientUsername)

	revokedBytes, err = json.Marshal(Access)
	if err != nil {
		return err
	}
	AccessIV := userlib.RandomBytes(16)
	revokedCiphertext := userlib.SymEnc(revokedEncryptionKey, AccessIV, revokedBytes)
	revokedHMACValue, err := userlib.HMACEval(revokedHMACKey, revokedCiphertext)
	if err != nil {
		return err
	}
	revokedData := append(revokedCiphertext, revokedHMACValue...)
	userlib.DatastoreSet(revokedAccessUUID, revokedData)

	// Get the fileMetaData and file from the Datastore
	FileMetaDataUUID := fileAccess.FileMetaDataUUID
	FMDData, ok := userlib.DatastoreGet(FileMetaDataUUID)
	if !ok {
		return errors.New("file does not exist")
	}
	if len(FMDData) < 64 {
		return errors.New("data has been tampered with")
	}
	FMDCiphertext := FMDData[:len(FMDData)-64]
	FMDHMACValue := FMDData[len(FMDData)-64:]
	computedFMDHMACValue, err := userlib.HMACEval(fileAccess.FMDHMACKey, FMDCiphertext)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(FMDHMACValue, computedFMDHMACValue) {
		return errors.New("data has been tampered with")
	}
	FMDBytes := userlib.SymDec(fileAccess.FMDEncryptionKey, FMDCiphertext)
	err = json.Unmarshal(FMDBytes, &fileMetaData)
	if err != nil {
		return err
	}
	fileContent, err := userdata.LoadFile(filename)
	if err != nil {
		return nil
	}
	file.Content = fileContent
	// Create new UUID for file and FMD
	newFirstUUID := uuid.New()
	newLastUUID := uuid.New()
	newFMDUUID := uuid.New()
	file.NextUUID = newLastUUID
	fileMetaData.FirstUUID = newFirstUUID
	fileAccess.FileMetaDataUUID = newFMDUUID

	// Create new FMD Keys
	newFMDEncryption := userlib.RandomBytes(16)
	newFMDHMAC := userlib.RandomBytes(16)
	// Create new file keys
	newFileEncryption := userlib.RandomBytes(16)
	newFileHMAC := userlib.RandomBytes(16)
	// Store the new keys
	fileAccess.FMDEncryptionKey = newFMDEncryption
	fileAccess.FMDHMACKey = newFMDHMAC
	fileMetaData.FileEncryptionKey = newFileEncryption
	fileMetaData.FileHMACKey = newFileHMAC
	// Encrypt the fileMetaData and file with new keys
	fileBytes, err := json.Marshal(file)
	if err != nil {
		return err
	}
	fileIV := userlib.RandomBytes(16)
	fileCiphertext := userlib.SymEnc(newFileEncryption, fileIV, fileBytes)
	fileHMACValue, err := userlib.HMACEval(newFileHMAC, fileCiphertext)
	if err != nil {
		return err
	}
	fileData := append(fileCiphertext, fileHMACValue...)
	userlib.DatastoreSet(newFirstUUID, fileData)

	FMDBytes, err = json.Marshal(fileMetaData)
	if err != nil {
		return err
	}
	FMDIV := userlib.RandomBytes(16)
	FMDCiphertext = userlib.SymEnc(newFMDEncryption, FMDIV, FMDBytes)
	FMDHMACValue, err = userlib.HMACEval(newFMDHMAC, FMDCiphertext)
	if err != nil {
		return err
	}
	FMDData = append(FMDCiphertext, FMDHMACValue...)
	userlib.DatastoreSet(newFMDUUID, FMDData)
	// Change all of the owner's children's Access struct
	for _, child := range fileAccess.Children {
		// Get the Access Data
		AccessUUID := child.AccessUUID
		AccessEncryptionKey := child.AccessKey
		AccessHMACKey := child.AccessHMAC
		AccessData, ok := userlib.DatastoreGet(AccessUUID)
		if !ok {
			return errors.New("file does not exist")
		}
		if len(AccessData) < 64 {
			return errors.New("data has been tampered with")
		}
		AccessCiphertext := AccessData[:len(AccessData)-64]
		AccessHMAC := AccessData[len(AccessData)-64:]
		computedHMACValue, err := userlib.HMACEval(AccessHMACKey, AccessCiphertext)
		if err != nil {
			return nil
		}
		if !userlib.HMACEqual(AccessHMAC, computedHMACValue) {
			return errors.New("data has been tampered with")
		}
		AccessBytes := userlib.SymDec(AccessEncryptionKey, AccessCiphertext)
		err = json.Unmarshal(AccessBytes, &Access)
		if err != nil {
			return err
		}

		// Change the Access data
		Access.FMDEncryptionKey = newFMDEncryption
		Access.FMDHMACKey = newFMDHMAC
		Access.FileMetaDataUUID = newFMDUUID

		// Store the Access
		AccessBytes, err = json.Marshal(Access)
		if err != nil {
			return err
		}
		AccessIV := userlib.RandomBytes(16)
		AccessCiphertext = userlib.SymEnc(child.AccessKey, AccessIV, AccessBytes)
		AccessHMACValue, err := userlib.HMACEval(child.AccessHMAC, AccessCiphertext)
		if err != nil {
			return err
		}
		AccessData = append(AccessCiphertext, AccessHMACValue...)
		userlib.DatastoreSet(child.AccessUUID, AccessData)
	}
	return nil
}

func hybridEncryption(recipientUsername string, plaintext []byte) (encryptedPrivateKey []byte, ciphertext []byte, err error) {
	// Get the public key of the recipient User
	publicKey, ok := userlib.KeystoreGet(recipientUsername + "publicKey")
	if !ok {
		return nil, nil, errors.New("key does not exist")
	}
	// Generate a random privateKey
	privateKey := userlib.RandomBytes(16)
	// Encrypt the random PrivateKey with the public key
	encryptedKey, err := userlib.PKEEnc(publicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	// Encrypt the plaintext using the random PrivateKey
	IV := userlib.RandomBytes(16)
	ciphertext = userlib.SymEnc(privateKey, IV, plaintext)
	// Return the encrypted random PrivateKey and the plaintext that is encrypted with the random PrivateKey
	return encryptedKey, ciphertext, err
}

func hybridDecryption(senderUsername string, recipientPrivateKey userlib.PrivateKeyType, ciphertext []byte, sig []byte, symKeyBytes []byte) (plaintext []byte, err error) {
	// Check for tampering using the Digital Signature
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "DSKey")

	if !ok {
		return nil, errors.New("key does not exist")
	}
	err = userlib.DSVerify(verifyKey, append(ciphertext, symKeyBytes...), sig)
	if err != nil {
		return nil, err
	}
	// Decrypt the symmetricKey using the given PrivateKey
	symKey, err := userlib.PKEDec(recipientPrivateKey, symKeyBytes)
	if err != nil {
		return nil, err
	}
	// Use the symmetricKey to decrypt the ciphertext
	plaintext = userlib.SymDec(symKey, ciphertext)

	return plaintext, nil

}
