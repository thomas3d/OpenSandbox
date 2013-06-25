/*
    OpenSandbox - build on Eashhook library and C#, 
	it allow you to run windows applications in a sandboxed environment
 
    Copyright (C) 2013 Thomas Jam Pedersen & Igor Polyakov

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    Please visit https://github.com/thomas3d/OpenSandbox for more information
    about the project and latest updates.
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using OpenSandbox;
using OpenSandbox.Logging;

namespace OpenSandbox.Crypto
{
    // Subclassing Win32Api to avoid lots of Win32Api. prefixes
    public class CryptoFunctionsHookLib : Win32Api
    {
        private static Hooks hooks_ = new Hooks(new Delegate[]
        {
            new WriteFile_Delegate(WriteFile_Hooked)
            // Hooking CloseHandle was leading to weird deadlocks and stack overflow
            // behavior, so not doing it, using workaround
            //new CloseHandle_Delegate(CloseHandle_Hooked));
        });

        public static Hooks Hooks { get { return hooks_; } }

        static CryptoFunctionsHookLib()
        {
            if (!Injection.PROFILING_ENABLED)
            {
                hooks_.Add(new CreateFile_Delegate(CreateFile_Hooked));
                hooks_.Add(new ReadFile_Delegate(ReadFile_Hooked));
            }
        }

        private static bool IsPathInExeDirOfNETHost(string fileName)
        {
            // TODO: GetGullPath and other functions do not handle path in the form "\\?\C:\Program Files\..."
            // for now just catching exception
            try
            {
                if (String.IsNullOrEmpty(Environment.GetEnvironmentVariable("OSBOXPARAMS"))) return false;
                return Path.GetDirectoryName(Path.GetFullPath(fileName)).StartsWith(
                    Path.GetDirectoryName(Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName)));
            }
            catch
            {
                return false;
            }
        }

        private static string AdjustPathToAssemblyExeDir(string fileName)
        {
            try
            {
                if (String.IsNullOrEmpty(Environment.GetEnvironmentVariable("OSBOXPARAMS"))) return fileName;
                string hostExeDir = Path.GetDirectoryName(Path.GetFullPath(Process.GetCurrentProcess().MainModule.FileName));
                string fileDir = Path.GetDirectoryName(Path.GetFullPath(fileName));
                if (!fileDir.StartsWith(hostExeDir)) return fileName;
                string assemblyExeDir = Path.GetDirectoryName(Utils.GetNetExeAssemblyPath());
                return assemblyExeDir + fileName.Remove(0, hostExeDir.Length);
            }
            catch
            {
                return fileName;
            }
        }

        internal static IntPtr CreateFile_Hooked(
            String lpFileName,
            UInt32 dwDesiredAccess,
            FileShareMode dwShareMode,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            CreateFileCreationDisposition dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile)
        {
            IntPtr result = new HookContext<IntPtr>(
                func => ((CreateFile_Delegate)func)(lpFileName, dwDesiredAccess,
                    dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                    dwFlagsAndAttributes, hTemplateFile),
                helper =>
                {
                    IntPtr helperResult = FileEncryptionLayer.CreateFile(lpFileName, dwDesiredAccess, dwShareMode,
                        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                        hTemplateFile);
                    // Path rewriting for .NET host app
                    if (helperResult == Win32Api.INVALID_HANDLE_VALUE)
                    {
                        uint errorCode = Win32Api.GetLastError();
                        if (IsPathInExeDirOfNETHost(lpFileName))
                        {
                            lpFileName = AdjustPathToAssemblyExeDir(lpFileName);
                            // log it before anything crashes. 
                            helperResult = FileEncryptionLayer.CreateFile(lpFileName, dwDesiredAccess, dwShareMode,
                                lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                                hTemplateFile);
                        }
                        else
                        {
                            Win32Api.SetLastError(errorCode);
                        }
                    }
                    return helperResult;
                },
                errorCode =>
                {
                    SetLastError(unchecked((uint)errorCode));
                    return IntPtr.Zero;
                },
                HookLogging.DefaultLogging, "[FILENAME]: {0}", lpFileName).Call();
            return result;
        }

        internal class BytesRead
        {
            private IntPtr bytesRead_;
            internal BytesRead(IntPtr lpNumberOfBytesRead)
            {
                bytesRead_ = lpNumberOfBytesRead;
            }

            public override string ToString()
            {
                if (bytesRead_ == IntPtr.Zero) return "<null>";
                return Marshal.ReadInt32(bytesRead_).ToString();
            }
        }

        internal static bool ReadFile_Hooked(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToRead,
            /*ref UInt32*/ IntPtr lpNumberOfBytesRead,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped)
        {
            BytesRead br = new BytesRead(lpNumberOfBytesRead);
            return new HookContext<bool>(
                func => ((ReadFile_Delegate)func)(hFile, lpBuffer, nNumberOfBytesToRead,
                    lpNumberOfBytesRead, lpOverlapped),
                helper => FileEncryptionLayer.ReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                    lpNumberOfBytesRead, lpOverlapped),
                errorCode =>
                {
                    SetLastError(unchecked((uint)errorCode));
                    return false;
                },
                HookLogging.DefaultLogging, "[hFile]: {0} [toRead]: {1} [Read]: {2}",
                hFile.ToString(), nNumberOfBytesToRead, br).Call();
        }

        internal static bool WriteFile_Hooked(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            /*ref UInt32*/ IntPtr lpNumberOfBytesWritten,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped)
        {
            return new HookContext<bool>(
                func => ((WriteFile_Delegate)func)(hFile, lpBuffer, nNumberOfBytesToWrite,
                    lpNumberOfBytesWritten, lpOverlapped),
                helper => FileEncryptionLayer.WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                    lpNumberOfBytesWritten, lpOverlapped),
                errorCode =>
                {
                    SetLastError(unchecked((uint)errorCode));
                    return false;
                },
                HookLogging.DefaultLogging, "[hFile]: {0}", hFile.ToString()).Call();
        }
    }
}
