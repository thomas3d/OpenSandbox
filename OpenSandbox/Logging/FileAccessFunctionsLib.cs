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
using EasyHook;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace OpenSandbox.Logging
{
    // Subclassing Win32Api to avoid lots of Win32Api. prefixes
    internal class FileAccessFunctionsHookLib : Win32Api
    {
        private static Hooks hooks_ = new Hooks(new Delegate[]
        {
            new NtOpenFile_Delegate(NtOpenFile_Hooked),
            new NtQueryAttributesFile_Delegate(NtQueryAttributesFile_Hooked),
            new NtQueryFullAttributesFile_Delegate(NtQueryFullAttributesFile_Hooked),
            new LoadLibraryEx_Delegate(LoadLibraryEx_Hooked)
        });

        internal static Hooks Hooks { get { return hooks_; } }

        static FileAccessFunctionsHookLib()
        {
            if (!Injection.PROFILING_ENABLED)
            {
                hooks_.Add(new NtCreateFile_Delegate(NtCreateFile_Hooked));
            }
        }

        private static string GetFileName(OBJECT_ATTRIBUTES ObjectAttributes)
        {
            UNICODE_STRING us = (UNICODE_STRING)Marshal.PtrToStructure(ObjectAttributes.ObjectName, typeof(UNICODE_STRING));
            string s = Marshal.PtrToStringUni(us.Buffer, us.Length / sizeof(char));
            return s.Replace(@"\??\C:\", @"C:\");
        }

        private static void DoAccessLogging(IHookHolderAndCallback injection, IntPtr ObjectAttributes)
        {
            try
            {
                OBJECT_ATTRIBUTES oa = (OBJECT_ATTRIBUTES)Marshal.PtrToStructure(ObjectAttributes, typeof(OBJECT_ATTRIBUTES));
                string lpFileName = GetFileName(oa);
                DoAccessLogging(injection, lpFileName);
            }
            catch { }
        }

        private static void DoAccessLogging(IHookHolderAndCallback injection, string lpFileName)
        {
            try
            {
                FileAccessLogger fileAccessLogger = ((Injection)injection).FileAccessLogger;
                if (fileAccessLogger != null)
                    fileAccessLogger.FileAccessed(lpFileName);
            }
            catch { }
        }

        internal static int NtCreateFile_Hooked(
            IntPtr FileHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr IoStatusBlock,
            IntPtr AllocationSize,
            uint FileAttributes,
            uint ShareAccess,
            uint CreateDisposition,
            uint CreateOptions,
            uint EaBuffer,
            uint EaLength
        )
        {
            return new HookContext<int>(
                func => ((NtCreateFile_Delegate)func)(FileHandle, DesiredAccess, ObjectAttributes,
                    IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
                    EaBuffer, EaLength),
                helper =>
                {
                    DoAccessLogging(helper.HookHolderAndCallback, ObjectAttributes);
                    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
                        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
                        EaBuffer, EaLength);
                },
                errorCode => errorCode,
                HookLogging.NoLogging, "").Call();
        }

        internal static int NtOpenFile_Hooked(
          IntPtr FileHandle,
          uint DesiredAccess,
          IntPtr ObjectAttributes,
          IntPtr IoStatusBlock,
          uint ShareAccess,
          uint OpenOptions
        )
        {
            return new HookContext<int>(
                func => ((NtOpenFile_Delegate)func)(FileHandle, DesiredAccess, ObjectAttributes,
                    IoStatusBlock, ShareAccess, OpenOptions),
                helper =>
                {
                    DoAccessLogging(helper.HookHolderAndCallback, ObjectAttributes);
                    return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
                },
                errorCode => errorCode,
                HookLogging.NoLogging, "").Call();
        }

        internal static int NtQueryAttributesFile_Hooked(
            IntPtr ObjectAttributes,
            IntPtr FileInformation
        )
        {
            return new HookContext<int>(
                func => ((NtQueryAttributesFile_Delegate)func)(ObjectAttributes, FileInformation),
                helper =>
                {
                    DoAccessLogging(helper.HookHolderAndCallback, ObjectAttributes);
                    return NtQueryAttributesFile(ObjectAttributes, FileInformation);
                },
                errorCode => errorCode,
                HookLogging.NoLogging, "").Call();
        }

        internal static int NtQueryFullAttributesFile_Hooked(
            IntPtr ObjectAttributes,
            IntPtr FileInformation
        )
        {
            return new HookContext<int>(
                func => ((NtQueryFullAttributesFile_Delegate)func)(ObjectAttributes, FileInformation),
                helper =>
                {
                    DoAccessLogging(helper.HookHolderAndCallback, ObjectAttributes);
                    return NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
                },
                errorCode => errorCode,
                HookLogging.NoLogging, "").Call();
        }

        internal static IntPtr LoadLibraryEx_Hooked(
            String lpFileName, IntPtr hFile, LoadLibraryExFlags dwFlags
        )
        {
            return new HookContext<IntPtr>(
                func => ((LoadLibraryEx_Delegate)func)(lpFileName, hFile, dwFlags),
                helper =>
                {
                    DoAccessLogging(helper.HookHolderAndCallback, lpFileName);
                    return LoadLibraryEx(lpFileName, hFile, dwFlags);
                },
                errorCode =>
                {
                    SetLastError(unchecked((uint)errorCode));
                    return IntPtr.Zero;
                },
                HookLogging.NoLogging, "").Call();

        }
    }
}
