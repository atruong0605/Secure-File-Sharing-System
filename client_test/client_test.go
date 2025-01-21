package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func measureBandwidth(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

func tamper_datastore() {
	userlib.DebugMsg("Tampering with the datastore entries.")
	mappedDatastore := userlib.DatastoreGetMap()
	for key, value := range mappedDatastore {
		userlib.DatastoreSet(key, userlib.Hash(value))
	}
}

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const bobPassword = "passwordBob"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const largeContent = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	//dorisFile := "dorisFile.txt"
	//eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Testing Checkpoint", func() {
		Specify("Testing Checkpoint", func() {

			userlib.DebugMsg("Initialize user Alice on Desktop.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initialize user Alice on Laptop.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to login with the incorrect password.")
			alice, err = client.GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initialize user Bob.")
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg(("Alice on Desktop storing file data."))
			err = aliceDesktop.StoreFile(aliceFile, []byte("This is a test file"))
			Expect(err).To(BeNil())

			userlib.DebugMsg(("Bob storing file data."))
			err = bob.StoreFile(aliceFile, []byte("This is a test file2"))
			Expect(err).To(BeNil())

			userlib.DebugMsg(("Alice on Laptop loading file data."))
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("This is a test file")))

			userlib.DebugMsg("Alice on Desktop changes the file data")
			err = aliceDesktop.StoreFile(aliceFile, []byte("Changes to the test file"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice on Desktop loading the file data")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("Changes to the test file")))

			userlib.DebugMsg("Testing namespacing")
			aliceData, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(aliceData).To(Equal([]byte("Changes to the test file")))
			bobData, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(bobData).To(Equal([]byte("This is a test file2")))

		})

		Specify("Testing Checkpoint: Authentication of User and Files (Integrity)", func() {
			userlib.DebugMsg("Initialize Alice User")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initialize user Bob.")
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			originalAliceData, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(originalAliceData).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			originalBobData, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(originalBobData).To(Equal([]byte(contentTwo)))

			tamper_datastore()

			userlib.DebugMsg("Trying to login using Alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Trying to login using Bob")
			bob, err = client.GetUser("bob", bobPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Trying to load tampered file using Alice")
			aliceData, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(aliceData).ToNot(Equal(contentOne))

			userlib.DebugMsg("Trying to append tampered file using Alice")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Trying to load tampered file using Bob")
			bobData, err := bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(bobData).ToNot(Equal(contentTwo))

		})

		Specify("Testing Checkpoint: Bandwidth and Append Efficieny", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing empty file")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initialize user Bob.")
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Testing AppendToFile when not in namespace")
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Testing AppendToFile")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		})

		Specify("Testing Checkpoint: Tampering invitations (integrity)", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", bobPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			tamper_datastore()

			userlib.DebugMsg("Trying to accept invitation with tampered data")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Testing: edge cases", func() {
			// InitUser
			// Return error if a user with the same username exists
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			// Return error if an empty username is provided
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			// GetUser
			// Return error is no intialized user for the given username
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
			// Return error if the user credentials are invalid
			alice, err = client.GetUser("alice", bobPassword)
			Expect(err).ToNot(BeNil())
			// Return error if the user struct was tampered
			tamper_datastore()
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing: edge cases", func() {

			// LoadFile
			// Returns error if the filename does not exist in personal file namespace
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			_, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			// Returns error if tampered
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			tamper_datastore()
			_, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Testing: edge cases", func() {
			// AppendToFile
			// Returns error if the filename does not exist in personal file namespace
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err := aliceDesktop.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
			// Returns error if tampered
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			tamper_datastore()
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing: edge cases", func() {

			// CreateInvitation
			// Returns error if the filename does not exist in personal file namespace
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			_, err = aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			// Returns error if the given recipientUsername does not exist
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			_, err = aliceDesktop.CreateInvitation(aliceFile, "jack")
			Expect(err).ToNot(BeNil())

			// Returns error if tampered with
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			tamper_datastore()
			_, err = aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
		Specify("Testing: edge cases", func() {

			// AcceptInvitation
			// Returns error if the user already has a file with a chosen filename in thier personal file namespace
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation(aliceDesktop.Username, invite, aliceFile)
			Expect(err).ToNot(BeNil())
			// Returns errors if the invitation is no longer valid due to revocation
			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation(aliceDesktop.Username, invite, bobFile)
			Expect(err).ToNot(BeNil())
			// Returns error if the invitationPtr cannot be verified or it has been tampered with
			invite, err = aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			tamper_datastore()
			err = bob.AcceptInvitation(aliceDesktop.Username, invite, bobFile)
			Expect(err).ToNot(BeNil())

		})
		Specify("Testing: edge cases", func() {

			// RevokeAccess
			// Returns error if the given filename does not exist in the caller's personal file namespace
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
			// Returns error if the filename is not currently shared with recipientUsername
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
			// Returns error if the user cannot be revoked due to malicious action
			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())
			tamper_datastore()
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Testing: multiple invitations", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			// Testing store, load, and append for child
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite1, aliceFile)
			Expect(err).To(BeNil())
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data1, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data1).To(Equal([]byte(contentOne)))
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data2, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte(contentOne + contentTwo)))

			// Testing invites
			invite2, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite2, aliceFile)
			Expect(err).To(BeNil())
			invite3, err := alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invite3, aliceFile)
			Expect(err).To(BeNil())

			invite4, err := doris.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("doris", invite4, aliceFile)
			Expect(err).To(BeNil())

			// Testing child of child store, load, and append
			err = charles.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data3, err := charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data3).To(Equal([]byte(contentOne)))
			err = charles.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data4, err := charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data4).To(Equal([]byte(contentOne + contentTwo)))

			// Revoke bob and test load and append
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			err = charles.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			// Testing other children can still use store, load, append

			err = doris.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data5, err := doris.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data5).To(Equal([]byte(contentOne)))
			err = doris.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data6, err := doris.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data6).To(Equal([]byte(contentOne + contentTwo)))

			err = eve.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			data7, err := eve.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data7).To(Equal([]byte(contentOne)))
			err = eve.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data8, err := eve.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data8).To(Equal([]byte(contentOne + contentTwo)))

		})

	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
})
