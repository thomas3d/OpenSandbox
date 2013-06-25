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
using System.Text;
using System.Runtime.InteropServices;

// TODO: get rid of all the pinvoke functions declarations except a couple used
// to test pinvoke delegate binding

namespace OpenSandbox
{
    public class Win32Api
    {
        #region Common Declarations

        /// <summary>
        /// Kernel32 dll name.
        /// </summary>
        internal const string Kernel32DllName = "kernel32.dll";

        internal const string KernelBaseDllName = "kernelbase.dll";

        /// <summary>
        /// Psapi dll name.
        /// </summary>
        internal const string PsapiDllName = "psapi.dll";

        /// <summary>
        /// Advapi32 dll name.
        /// </summary>
        internal const string Advapi32DllName = "advapi32.dll";

        /// <summary>
        /// Ntdll dll name.
        /// </summary>
        internal const string NtdllDllName = "ntdll.dll";

        /// <summary>
        /// User32 dll name.
        /// </summary>
        internal const string User32DllName = "user32.dll";

        /// <summary>
        /// See CopyProgressRoutine topic in MSDN. 
        /// </summary>
        internal enum CopyProgressRoutineCallbackReason : uint
        {
            CALLBACK_CHUNK_FINISHED = 0x00000000,
            CALLBACK_STREAM_SWITCH = 0x00000001
        }

        /// <summary>
        /// See CopyProgressRoutine topic in MSDN. 
        /// </summary>
        internal enum CopyProgressRoutineResult : uint
        {
            PROGRESS_CONTINUE = 0,
            PROGRESS_CANCEL = 1,
            PROGRESS_STOP = 2,
            PROGRESS_QUIET = 3
        }

        /// <summary>
        /// See CopyProgressRoutine topic in MSDN. 
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate CopyProgressRoutineResult CopyProgressRoutine(Int64 TotalFileSize, Int64 TotalBytesTransferred, Int64 StreamSize,
            Int64 StreamBytesTransferred, UInt32 dwStreamNumber, CopyProgressRoutineCallbackReason dwCallbackReason, IntPtr hSourceFile,
            IntPtr hDestinationFile, IntPtr lpData);

        /// <summary>
        /// See FileIOCompletionRoutine topic in MSDN. 
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate void FileIOCompletionRoutine(UInt32 dwErrorCode, UInt32 dwNumberOfBytesTransfered, /*ref OVERLAPPED*/ IntPtr lpOverlapped);

        /// <summary>
        /// See CreateFile topic in MSDN. 
        /// </summary>
        [Flags]
        internal enum FileCreationFlags : uint
        {
            FILE_FLAG_WRITE_THROUGH         = 0x80000000,
            FILE_FLAG_OVERLAPPED            = 0x40000000,
            FILE_FLAG_NO_BUFFERING          = 0x20000000,
            FILE_FLAG_RANDOM_ACCESS         = 0x10000000,
            FILE_FLAG_SEQUENTIAL_SCAN       = 0x08000000,
            FILE_FLAG_DELETE_ON_CLOSE       = 0x04000000,
            FILE_FLAG_BACKUP_SEMANTICS      = 0x02000000,
            FILE_FLAG_POSIX_SEMANTICS       = 0x01000000,
            FILE_FLAG_OPEN_REPARSE_POINT    = 0x00200000,
            FILE_FLAG_OPEN_NO_RECALL        = 0x00100000,
            FILE_FLAG_FIRST_PIPE_INSTANCE   = 0x00080000
        }

        /// <summary>
        /// See CreateFile topic in MSDN. 
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            internal UInt32 nLength;
            internal IntPtr lpSecurityDescriptor;
            //Use UInt32 to marshal BOOL data type because using Boolean leads to crash.
            internal UInt32 bInheritHandle;
        }

        /// <summary>
        /// See RegCreateKeyEx topic in MSDN.
        /// </summary>
        internal enum RegOption : uint
        {
            REG_OPTION_RESERVED = 0x00000000,
            REG_OPTION_NON_VOLATILE = 0x00000000,
            REG_OPTION_VOLATILE = 0x00000001,
            REG_OPTION_CREATE_LINK = 0x00000002,
            REG_OPTION_BACKUP_RESTORE = 0x00000004,
            REG_OPTION_OPEN_LINK = 0x00000008
        }

        /// <summary>
        /// See FILETIME topic in MSDN.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct FILETIME
        {
            internal UInt32 dwLowDateTime;
            internal UInt32 dwHighDateTime;
            internal long AsLong
            {
                get
                {
                    return unchecked((long)(((ulong)dwHighDateTime << 32) | dwLowDateTime));
                }
            }
        }

        /// <summary>
        /// See RegEnumValue in MSDN.
        /// </summary>
        internal enum RegValueType : uint
        {
            REG_NONE                        = 0,
            REG_SZ                          = 1,
            REG_EXPAND_SZ                   = 2,
            REG_BINARY                      = 3,
            REG_DWORD                       = 4,
            REG_DWORD_LITTLE_ENDIAN         = 4,
            REG_DWORD_BIG_ENDIAN            = 5,
            REG_LINK                        = 6,
            REG_MULTI_SZ                    = 7,
            REG_RESOURCE_LIST               = 8,
            REG_FULL_RESOURCE_DESCRIPTOR    = 9, 
            REG_RESOURCE_REQUIREMENTS_LIST  = 10,
            REG_QWORD                       = 11,
            REG_QWORD_LITTLE_ENDIAN         = 11 
        }

        /// <summary>
        /// See SECURITY_INFORMATION in MSDN.
        /// </summary>
        internal enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            LABEL_SECURITY_INFORMATION = 0x00000010,
            PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000,
            PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
            UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
            UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OVERLAPPEDOffset
        {
            UInt32 Offset;
            UInt32 OffsetHigh;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct OVERLAPPEDUnion
        {
            [FieldOffset(0)]
            OVERLAPPEDOffset Offset;
            [FieldOffset(0)]
            IntPtr Pointer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OVERLAPPED
        {
            UIntPtr Internal;
            UIntPtr InternalHigh;
            OVERLAPPEDUnion Union;
            IntPtr hEvent;
        };

        internal static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        #endregion

        #region File Management API

        internal const string CATEGORY_FILES = "Files";

        internal enum FileSecurity : uint
        {
            GENERIC_READ = 0x80000000
        }

        #region CloseHandle function

        internal const String CloseHandleFuncName = "CloseHandle";

        [DllImport(Kernel32DllName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern Boolean CloseHandle(
            IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean CloseHandle_Delegate(
            IntPtr hObject);

        #endregion

        #region FindFile

        internal const int MAX_ALTERNATE = 14;

        //[StructLayout(LayoutKind.Sequential)]
        //public struct FILETIME
        //{
        //    public uint dwLowDateTime;
        //    public uint dwHighDateTime;
        //};

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct WIN32_FIND_DATA
        {
            internal FileAttributes dwFileAttributes;
            internal FILETIME ftCreationTime;
            internal FILETIME ftLastAccessTime;
            internal FILETIME ftLastWriteTime;
            internal uint nFileSizeHigh;
            internal uint nFileSizeLow;
            internal uint dwReserved0;
            internal uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_ALTERNATE)]
            internal string cAlternate;
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode)]
        internal static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        internal enum FINDEX_INFO_LEVELS
        {
            FindExInfoStandard = 0,
            // TODO: the following option increases speed of finding files on win 7 and win 8. use it
            FindExInfoBasic = 1
        }

        internal enum FINDEX_SEARCH_OPS
        {
            FindExSearchNameMatch = 0,
            FindExSearchLimitToDirectories = 1,
            FindExSearchLimitToDevices = 2
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode)]
        internal static extern IntPtr FindFirstFileEx(
            string lpFileName,
            FINDEX_INFO_LEVELS fInfoLevelId,
            out WIN32_FIND_DATA lpFindFileData,
            FINDEX_SEARCH_OPS fSearchOp,
            IntPtr lpSearchFilter,
            int dwAdditionalFlags);

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode)]
        internal static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport(Kernel32DllName)]
        internal static extern bool FindClose(IntPtr hFindFile);
        
        #endregion

        #region CopyFile function

        internal const String CopyFileFuncName = "CopyFileW";

        [DllImport(Kernel32DllName, CallingConvention = CallingConvention.StdCall, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CopyFile(
            String lpExistingFileName, 
            String lpNewFileName, 
            Boolean bFailIfExists);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean CopyFile_Delegate(
            String lpExistingFileName, 
            String lpNewFileName, 
            Boolean bFailIfExists);

        #endregion

        #region CopyFileEx function

        internal const String CopyFileExFuncName = "CopyFileExW";

        internal enum CopyFileExCopyFlags : uint
        {
            COPY_FILE_FAIL_IF_EXISTS                = 0x00000001,
            COPY_FILE_RESTARTABLE                   = 0x00000002,
            COPY_FILE_OPEN_SOURCE_FOR_WRITE         = 0x00000004,
            COPY_FILE_ALLOW_DECRYPTED_DESTINATION   = 0x00000008,
            COPY_FILE_COPY_SYMLINK                  = 0x00000800
        }

        [DllImport(Kernel32DllName, CallingConvention = CallingConvention.StdCall, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CopyFileEx(
            String lpExistingFileName, 
            String lpNewFileName,
            CopyProgressRoutine lpProgressRoutine, 
            IntPtr lpData, 
            /*ref Int32*/ IntPtr pbCancel, 
            CopyFileExCopyFlags dwCopyFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean CopyFileEx_Delegate(
            String lpExistingFileName, 
            String lpNewFileName,
            CopyProgressRoutine lpProgressRoutine, 
            IntPtr lpData,
            /*ref Int32*/ IntPtr pbCancel, 
            CopyFileExCopyFlags dwCopyFlags);

        #endregion

        #region CreateFile function

        internal const String CreateFileFuncName = "CreateFileW";

        internal enum FileShareMode : uint
        {
            FILE_SHARE_READ = 0x00000001,
            FILE_SHARE_WRITE = 0x00000002,
            FILE_SHARE_DELETE = 0x00000004
        }

        internal enum CreateFileCreationDisposition : uint
        {
            CREATE_NEW = 1,
            CREATE_ALWAYS = 2,
            OPEN_EXISTING = 3,
            OPEN_ALWAYS = 4,
            TRUNCATE_EXISTING = 5
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFile(
          String lpFileName,
          UInt32 dwDesiredAccess,
          FileShareMode dwShareMode,
          /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
          CreateFileCreationDisposition dwCreationDisposition,
          UInt32 dwFlagsAndAttributes,
          IntPtr hTemplateFile);

        [DllFunction(Kernel32DllName, CreateFileFuncName, CATEGORY_FILES)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr CreateFile_Delegate(
          String lpFileName,
          UInt32 dwDesiredAccess,
          FileShareMode dwShareMode,
          /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
          CreateFileCreationDisposition dwCreationDisposition,
          UInt32 dwFlagsAndAttributes,
          IntPtr hTemplateFile);

        #endregion

        #region CreateHardLink function

        internal const String CreateHardLinkFuncName = "CreateHardLinkW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CreateHardLink(String lpFileName, String lpExistingFileName, IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean CreateHardLink_Delegate(String lpFileName, String lpExistingFileName, IntPtr lpSecurityAttributes);

        #endregion

        #region DeleteFile function

        internal const String DeleteFileFuncName = "DeleteFileW";

        [DllImport(Kernel32DllName, CallingConvention = CallingConvention.StdCall, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean DeleteFile(String lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean DeleteFile_Delegate(String lpFileName);

        #endregion

        #region GetFileSize function

        internal const String GetFileSizeFuncName = "GetFileSize";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern UInt32 GetFileSize(IntPtr hFile, /*ref UInt32*/ IntPtr lpFileSizeHigh);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate UInt32 GetFileSize_Delegate(IntPtr hFile, /*ref UInt32*/ IntPtr lpFileSizeHigh);

        #endregion

        #region GetFileSizeEx function

        internal const String GetFileSizeExFuncName = "GetFileSizeEx";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean GetFileSizeEx(IntPtr hFile, /*ref Int64*/ IntPtr lpFileSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean GetFileSizeEx_Delegate(IntPtr hFile, /*ref Int64*/ IntPtr lpFileSize);

        #endregion

        #region MoveFile function

        internal const String MoveFileFuncName = "MoveFileW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean MoveFile(String lpExistingFileName, String lpNewFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean MoveFile_Delegate(String lpExistingFileName, String lpNewFileName);

        #endregion

        #region MoveFileEx function

        internal const String MoveFileExFuncName = "MoveFileExW";

        internal enum MoveFileExFlags : uint
        {
            MOVEFILE_REPLACE_EXISTING = 0x00000001,
            MOVEFILE_COPY_ALLOWED = 0x00000002,
            MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004,
            MOVEFILE_WRITE_THROUGH = 0x00000008,
            MOVEFILE_CREATE_HARDLINK = 0x00000010,
            MOVEFILE_FAIL_IF_NOT_TRACKABLE = 0x00000020
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean MoveFileEx(
            String lpExistingFileName,
            String lpNewFileName,
            MoveFileExFlags dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean MoveFileEx_Delegate(
            String lpExistingFileName,
            String lpNewFileName,
            MoveFileExFlags dwFlags);

        #endregion

        #region OpenFile function

        internal const String OpenFileFuncName = "OpenFile";

        [Flags]
        internal enum OpenFileStyle : uint
        {
            OF_CANCEL = 0x00000800,  // Ignored. For a dialog box with a Cancel button, use OF_PROMPT.
            OF_CREATE = 0x00001000,  // Creates a new file. If file exists, it is truncated to zero (0) length.
            OF_DELETE = 0x00000200,  // Deletes a file.
            OF_EXIST = 0x00004000,  // Opens a file and then closes it. Used to test that a file exists
            OF_PARSE = 0x00000100,  // Fills the OFSTRUCT structure, but does not do anything else.
            OF_PROMPT = 0x00002000,  // Displays a dialog box if a requested file does not exist 
            OF_READ = 0x00000000,  // Opens a file for reading only.
            OF_READWRITE = 0x00000002,  // Opens a file with read/write permissions.
            OF_REOPEN = 0x00008000,  // Opens a file by using information in the reopen buffer.

            // For MS-DOS–based file systems, opens a file with compatibility mode, allows any process on a 
            // specified computer to open the file any number of times.
            // Other efforts to open a file with other sharing modes fail. This flag is mapped to the 
            // FILE_SHARE_READ|FILE_SHARE_WRITE flags of the CreateFile function.
            OF_SHARE_COMPAT = 0x00000000,

            // Opens a file without denying read or write access to other processes.
            // On MS-DOS-based file systems, if the file has been opened in compatibility mode
            // by any other process, the function fails.
            // This flag is mapped to the FILE_SHARE_READ|FILE_SHARE_WRITE flags of the CreateFile function.
            OF_SHARE_DENY_NONE = 0x00000040,

            // Opens a file and denies read access to other processes.
            // On MS-DOS-based file systems, if the file has been opened in compatibility mode,
            // or for read access by any other process, the function fails.
            // This flag is mapped to the FILE_SHARE_WRITE flag of the CreateFile function.
            OF_SHARE_DENY_READ = 0x00000030,

            // Opens a file and denies write access to other processes.
            // On MS-DOS-based file systems, if a file has been opened in compatibility mode,
            // or for write access by any other process, the function fails.
            // This flag is mapped to the FILE_SHARE_READ flag of the CreateFile function.
            OF_SHARE_DENY_WRITE = 0x00000020,

            // Opens a file with exclusive mode, and denies both read/write access to other processes.
            // If a file has been opened in any other mode for read/write access, even by the current process,
            // the function fails.
            OF_SHARE_EXCLUSIVE = 0x00000010,

            // Verifies that the date and time of a file are the same as when it was opened previously.
            // This is useful as an extra check for read-only files.
            OF_VERIFY = 0x00000400,

            // Opens a file for write access only.
            OF_WRITE = 0x00000001
        }

        const Int16 OFS_MAXPATHNAME = 128;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct OFSTRUCT
        {
            Byte cBytes;
            Byte fFixedDisk;
            UInt16 nErrCode;
            UInt16 Reserved1;
            UInt16 Reserved2;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = OFS_MAXPATHNAME)]
            String szPathName;
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern Int32 OpenFile(
            String lpFileName,
            /*ref OFSTRUCT*/ IntPtr lpReOpenBuff,
            OpenFileStyle uStyle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        internal delegate Int32 OpenFile_Delegate(
            String lpFileName,
            /*ref OFSTRUCT*/ IntPtr lpReOpenBuff,
            OpenFileStyle uStyle);

        #endregion

        internal const string CATEGORY_FILE_ACCESS = "FileAccess";

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        internal enum ObjectAttributes : uint
        {
            OBJ_CASE_INSENSITIVE = 0x40
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_ATTRIBUTES
        {
            internal uint Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        #region NtCreateFile function

        internal const String NtCreateFileFuncName = "NtCreateFile";

        [DllImport(NtdllDllName)]
        internal static extern int NtCreateFile(
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
        );

        [DllFunction(NtdllDllName, NtCreateFileFuncName, CATEGORY_FILE_ACCESS)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtCreateFile_Delegate(
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
        );

        #endregion

        #region NtOpenFile function

        internal const String NtOpenFileFuncName = "NtOpenFile";

        [DllImport(NtdllDllName)]
        internal static extern int NtOpenFile(
          IntPtr FileHandle,
          uint DesiredAccess,
            /*ref OBJECT_ATTRIBUTES*/ IntPtr ObjectAttributes,
          IntPtr IoStatusBlock,
          uint ShareAccess,
          uint OpenOptions
        );

        [DllFunction(NtdllDllName, NtOpenFileFuncName, CATEGORY_FILE_ACCESS)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtOpenFile_Delegate(
          IntPtr FileHandle,
          uint DesiredAccess,
            /*ref OBJECT_ATTRIBUTES*/ IntPtr ObjectAttributes,
          IntPtr IoStatusBlock,
          uint ShareAccess,
          uint OpenOptions
        );

        #endregion

        #region NtQueryAttributesFile function

        internal const String NtQueryAttributesFileFuncName = "NtQueryAttributesFile";

        [DllImport(NtdllDllName)]
        internal static extern int NtQueryAttributesFile(
            IntPtr ObjectAttributes,
            IntPtr FileInformation
        );

        [DllFunction(NtdllDllName, NtQueryAttributesFileFuncName, CATEGORY_FILE_ACCESS)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtQueryAttributesFile_Delegate(
            IntPtr ObjectAttributes,
            IntPtr FileInformation
        );

        #endregion

        #region NtQueryFullAttributesFile function

        internal const String NtQueryFullAttributesFileFuncName = "NtQueryFullAttributesFile";

        [DllImport(NtdllDllName)]
        internal static extern int NtQueryFullAttributesFile(
            IntPtr ObjectAttributes,
            IntPtr FileInformation
        );

        [DllFunction(NtdllDllName, NtQueryFullAttributesFileFuncName, CATEGORY_FILE_ACCESS)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtQueryFullAttributesFile_Delegate(
            IntPtr ObjectAttributes,
            IntPtr FileInformation
        );

        #endregion
        #region OpenFileById function

        internal const String OpenFileByIdFuncName = "OpenFileById";

        internal enum FILE_ID_TYPE 
        {
            FileIdType = 0,
            ObjectIdType = 1,
            MaximumFileIdType = 2
        } 

        [StructLayout(LayoutKind.Explicit)]
        internal struct DUMMYUNIONNAME
        {
            [FieldOffset(0)]
            Int64 FileId;
            [FieldOffset(0)]
            Guid ObjectId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct FILE_ID_DESCRIPTOR
        {
            UInt32 dwSize;  
            FILE_ID_TYPE Type; 
            DUMMYUNIONNAME dummyUnionName;
        }

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern IntPtr OpenFileById(
            IntPtr hFile,
            /*ref FILE_ID_DESCRIPTOR*/ IntPtr lpFileID,
            UInt32 dwDesiredAccess,
            FileShareMode dwShareMode,
            IntPtr lpSecurityAttributes,
            FileCreationFlags dwFlags);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate IntPtr OpenFileById_Delegate(
            IntPtr hFile,
            /*ref FILE_ID_DESCRIPTOR*/ IntPtr lpFileID,
            UInt32 dwDesiredAccess,
            FileShareMode dwShareMode,
            IntPtr lpSecurityAttributes,
            FileCreationFlags dwFlags);

        #endregion

        #region ReadFile function

        internal const String ReadFileFuncName = "ReadFile";

        [DllImport(Kernel32DllName, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern Boolean ReadFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToRead,
            /*ref UInt32*/ IntPtr lpNumberOfBytesRead,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped);

        [DllFunction(Kernel32DllName, ReadFileFuncName, CATEGORY_FILES)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean ReadFile_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToRead,
            /*ref UInt32*/ IntPtr lpNumberOfBytesRead,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped);

        #endregion

        #region ReadFileEx function

        internal const String ReadFileExFuncName = "ReadFileEx";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean ReadFileEx(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToRead,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped,
            FileIOCompletionRoutine lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean ReadFileEx_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToRead,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped,
            FileIOCompletionRoutine lpCompletionRoutine);

        #endregion

        #region ReOpenFile function

        internal const String ReOpenFileFuncName = "ReOpenFile";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern IntPtr ReOpenFile(
          IntPtr hOriginalFile,
          UInt32 dwDesiredAccess,
          FileShareMode dwShareMode,
          UInt32 dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate IntPtr ReOpenFile_Delegate(
          IntPtr hOriginalFile,
          UInt32 dwDesiredAccess,
          FileShareMode dwShareMode,
          UInt32 dwFlags);

        #endregion

        #region ReplaceFile function

        internal const String ReplaceFileFuncName = "ReplaceFileW";

        [Flags]
        internal enum ReplaceFileFlags : uint
        {
            REPLACEFILE_WRITE_THROUGH = 0x00000001,
            REPLACEFILE_IGNORE_MERGE_ERRORS = 0x00000002
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean ReplaceFile(
            String lpReplacedFileName,
            String lpReplacementFileName, 
            String lpBackupFileName,
            ReplaceFileFlags dwReplaceFlags, 
            IntPtr lpExclude, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean ReplaceFile_Delegate(
            String lpReplacedFileName,
            String lpReplacementFileName,
            String lpBackupFileName,
            ReplaceFileFlags dwReplaceFlags,
            IntPtr lpExclude, IntPtr lpReserved);

        #endregion

        #region SetFilePointer function

        internal const String SetFilePointerFuncName = "SetFilePointer";

        internal enum SetFilePointerMoveMethod : uint
        {
            FILE_BEGIN     = 0,
            FILE_CURRENT   = 1,
            FILE_END       = 2
        }

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern UInt32 SetFilePointer(
            IntPtr hFile,
            Int32 lDistanceToMove,
            /*ref Int32*/ IntPtr lpDistanceToMoveHigh,
            SetFilePointerMoveMethod dwMoveMethod);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate UInt32 SetFilePointer_Delegate(
            IntPtr hFile,
            Int32 lDistanceToMove,
            /*ref Int32*/ IntPtr lpDistanceToMoveHigh,
            SetFilePointerMoveMethod dwMoveMethod);

        #endregion

        #region SetFilePointerEx function

        internal const String SetFilePointerExFuncName = "SetFilePointerEx";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean SetFilePointerEx(
            IntPtr hFile,
            Int64 liDistanceToMove,
            /*ref Int64*/ IntPtr lpNewFilePointer,
            SetFilePointerMoveMethod dwMoveMethod);

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean SetFilePointerEx(
            IntPtr hFile,
            Int64 liDistanceToMove,
            ref Int64 lpNewFilePointer,
            SetFilePointerMoveMethod dwMoveMethod);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean SetFilePointerEx_Delegate(
            IntPtr hFile,
            Int64 liDistanceToMove,
            /*ref Int64*/ IntPtr lpNewFilePointer,
            SetFilePointerMoveMethod dwMoveMethod);

        #endregion

        #region Wow64DisableWow64FsRedirection function

        internal const String Wow64DisableWow64FsRedirectionFuncName = "Wow64DisableWow64FsRedirection";

         [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean Wow64DisableWow64FsRedirection(/*ref IntPtr*/ IntPtr oldValue);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
         internal delegate Boolean Wow64DisableWow64FsRedirection_Delegate(/*ref IntPtr*/ IntPtr oldValue);

        #endregion

        #region Wow64EnableWow64FsRedirection function

        internal const String Wow64EnableWow64FsRedirectionFuncName = "Wow64EnableWow64FsRedirection";

        [DllImport(Kernel32DllName, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)] 
        internal static extern Boolean Wow64EnableWow64FsRedirection(
            [MarshalAs(UnmanagedType.U1)] Boolean wow64FsEnableRedirection);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        internal delegate Boolean Wow64EnableWow64FsRedirection_Delegate(
            [MarshalAs(UnmanagedType.U1)] Boolean wow64FsEnableRedirection);

        #endregion

        #region Wow64RevertWow64FsRedirection function

        internal const String Wow64RevertWow64FsRedirectionFuncName = "Wow64RevertWow64FsRedirection";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean Wow64RevertWow64FsRedirection(IntPtr oldValue);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean Wow64RevertWow64FsRedirection_Delegate(IntPtr oldValue);

        #endregion

        #region WriteFile function

        internal const String WriteFileFuncName = "WriteFile";

        [DllImport(Kernel32DllName, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern Boolean WriteFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            /*ref UInt32*/ IntPtr lpNumberOfBytesWritten,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped);

        [DllFunction(Kernel32DllName, WriteFileFuncName, CATEGORY_FILES)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean WriteFile_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            /*ref UInt32*/ IntPtr lpNumberOfBytesWritten,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped);

        #endregion

        #region WriteFileEx function

        internal const String WriteFileExFuncName = "WriteFileEx";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern Boolean WriteFileEx(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped,
            FileIOCompletionRoutine lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean WriteFileEx_Delegate(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped,
            FileIOCompletionRoutine lpCompletionRoutine);

        #endregion

        #endregion

        #region Directory Management API

        #region CreateDirectory function

        internal const String CreateDirectoryFuncName = "CreateDirectoryW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CreateDirectory(
            String lpPathName,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean CreateDirectory_Delegate(
            String lpPathName,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes);

        #endregion

        #region CreateDirectoryEx function

        internal const String CreateDirectoryExFuncName = "CreateDirectoryExW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean CreateDirectoryEx(
            String lpTemplateDirectory,
            String lpNewDirectory,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean CreateDirectoryEx_Delegate(
            String lpTemplateDirectory,
            String lpNewDirectory,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes);

        #endregion

        #region RemoveDirectory function

        internal const String RemoveDirectoryFuncName = "RemoveDirectoryW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean RemoveDirectory(String lpPathName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean RemoveDirectory_Delegate(String lpPathName);

        #endregion

        #region SetCurrentDirectory function

        internal const String SetCurrentDirectoryFuncName = "SetCurrentDirectoryW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean SetCurrentDirectory(String lpPathName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean SetCurrentDirectory_Delegate(String lpPathName);

        #endregion

        #endregion

        #region Service Functions API

        #region CreateService function

        internal const String CreateServiceFuncName = "CreateServiceW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateService(
            IntPtr hSCManager,
            String lpServiceName,
            String lpDisplayName,
            UInt32 dwDesiredAccess,
            UInt32 dwServiceType,
            UInt32 dwStartType,
            UInt32 dwErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            /*ref UInt32*/ IntPtr lpdwTagId,
            String lpDependencies,
            String lpServiceStartName,
            String lpPassword);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr CreateService_Delegate(
            IntPtr hSCManager,
            String lpServiceName,
            String lpDisplayName,
            UInt32 dwDesiredAccess,
            UInt32 dwServiceType,
            UInt32 dwStartType,
            UInt32 dwErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            /*ref UInt32*/ IntPtr lpdwTagId,
            String lpDependencies,
            String lpServiceStartName,
            String lpPassword);

        #endregion

        #region DeleteService function

        internal const String DeleteServiceFuncName = "DeleteService";

        [DllImport(Advapi32DllName, SetLastError = true)]
        internal static extern Boolean DeleteService(
            IntPtr hService);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Boolean DeleteService_Delegate(
            IntPtr hService);

        #endregion

        #region StartService function

        internal const String StartServiceFuncName = "StartServiceW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean StartService(
            IntPtr hService,
            UInt32 dwNumServiceArgs,
            String[] lpServiceArgVectors);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate Boolean StartService_Delegate(
            IntPtr hService,
            UInt32 dwNumServiceArgs,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPTStr, SizeParamIndex = 1)] 
            String[] lpServiceArgVectors);

        #endregion

        #endregion

        #region Registry Functions API

        internal const string CATEGORY_REGISTRY = "Registry";

        internal enum RegPredefinedKeys : int
        {
            HKEY_CLASSES_ROOT = unchecked((int)0x80000000),
            HKEY_CURRENT_USER = unchecked((int)0x80000001),
            HKEY_LOCAL_MACHINE = unchecked((int)0x80000002),
            HKEY_USERS = unchecked((int)0x80000003),
            HKEY_PERFORMANCE_DATA = unchecked((int)0x80000004),
            HKEY_CURRENT_CONFIG = unchecked((int)0x80000005),
            HKEY_DYN_DATA = unchecked((int)0x80000006),
            HKEY_CURRENT_USER_LOCAL_SETTINGS = unchecked((int)0x80000007)
        }

        internal enum KeySecurity : int
        {
            KEY_QUERY_VALUE = 0x0001,
            KEY_SET_VALUE = 0x0002,
            KEY_ENUMERATE_SUB_KEYS = 0x0008,
            KEY_NOTIFY = 0x0010,
            DELETE = 0x10000,
            STANDARD_RIGHTS_READ = 0x20000,
            KEY_READ = 0x20019,
            KEY_WRITE = 0x20006,
            KEY_ALL_ACCESS = 0xF003F,
            MAXIMUM_ALLOWED = 0x2000000
        }

        #region NtOpenKey function

        internal const String NtOpenKeyFuncName = "NtOpenKey";

        [DllImport("ntdll.dll")]
        internal static extern int NtOpenKey(out IntPtr KeyHandle, uint AccessMask,
            IntPtr ObjectAttributes);

        [DllFunction(NtdllDllName, NtOpenKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtOpenKey_Delegate(out IntPtr KeyHandle, uint AccessMask,
            IntPtr ObjectAttributes);

        #endregion

        #region NtQueryKey function

        internal enum KeyInformationClass : uint
        {
            KeyBasicInformation = 0,
            KeyNodeInformation = 1,
            KeyFullInformation = 2,
            KeyNameInformation = 3,
            KeyCachedInformation = 4,
            KeyFlagsInformation = 5,
            KeyVirtualizationInformation = 6,
            KeyHandleTagsInformation = 7,
            MaxKeyInfoClass = 8 
        }

        internal const String NtQueryKeyFuncName = "NtQueryKey";

        [DllImport("ntdll.dll")]
        internal static extern int NtQueryKey(IntPtr KeyHandle,
            KeyInformationClass KeyInformationClass,
            IntPtr KeyInformation, uint Length, out uint ResultLength);

        [DllFunction(NtdllDllName, NtQueryKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int NtQueryKey_Delegate(IntPtr KeyHandle,
            KeyInformationClass KeyInformationClass,
            IntPtr KeyInformation, uint Length, out uint ResultLength);

        #endregion

        #region NtClose function

        internal const String NtCloseFuncName = "NtClose";

        [DllImport("ntdll.dll")]
        internal static extern int NtClose(IntPtr Handle);

        #endregion

        #region RegCloseKey function

        internal const String RegCloseKeyFuncName = "RegCloseKey";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegCloseKey(IntPtr hKey);

        [DllFunction(Advapi32DllName, RegCloseKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegCloseKey_Delegate(IntPtr hKey);

        #endregion

        #region RegConnectRegistry function

        internal const String RegConnectRegistryFuncName = "RegConnectRegistryW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegConnectRegistry(
            String lpMachineName, 
            UIntPtr hKey, 
           /*ref IntPtr*/ IntPtr phkResult);

        [DllFunction(Advapi32DllName, RegConnectRegistryFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegConnectRegistry_Delegate(
            String lpMachineName, 
            UIntPtr hKey, 
            /*ref IntPtr*/ IntPtr phkResult);

        #endregion

        #region RegCopyTree function

        internal const String RegCopyTreeFuncName = "RegCopyTreeW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegCopyTree(
            IntPtr hKeySrc, 
            String lpSubKey, 
            IntPtr hKeyDest);

        [DllFunction(Advapi32DllName, RegCopyTreeFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegCopyTree_Delegate(
            IntPtr hKeySrc, 
            String lpSubKey, 
            IntPtr hKeyDest);

        #endregion

        #region RegCreateKey function

        internal const String RegCreateKeyFuncName = "RegCreateKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegCreateKey(
            IntPtr hKey,
            String lpSubKey,
            /*ref IntPtr*/ out IntPtr phkResult);

        [DllFunction(Advapi32DllName, RegCreateKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegCreateKey_Delegate(
            IntPtr hKey,
            String lpSubKey,
            /*ref IntPtr*/ out IntPtr phkResult);

        #endregion

        #region RegCreateKeyEx function

        internal const String RegCreateKeyExFuncName = "RegCreateKeyExW";

        internal enum RegKeyDisposition : uint
        {
            REG_CREATED_NEW_KEY = 0x00000001,
            REG_OPENED_EXISTING_KEY = 0x00000002
        }

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegCreateKeyEx(
            IntPtr hKey, 
            String lpSubKey, 
            int Reserved,
            String lpClass,
            RegOption dwOptions,
            KeySecurity samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            IntPtr lpdwDisposition);

        [DllFunction(Advapi32DllName, RegCreateKeyExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegCreateKeyEx_Delegate(
            IntPtr hKey,
            String lpSubKey,
            int Reserved,
            String lpClass,
            RegOption dwOptions,
            KeySecurity samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            IntPtr lpdwDisposition);

        #endregion

        #region RegCreateKeyTransacted function

        internal const String RegCreateKeyTransactedFuncName = "RegCreateKeyTransactedW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegCreateKeyTransacted(
            UIntPtr hKey,
            String lpSubKey,
            UInt32 Reserved,
            String lpClass,
            RegOption dwOptions,
            KeySecurity samDesired,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            /*ref IntPtr*/ IntPtr phkResult,
            /*ref RegKeyDisposition*/ IntPtr lpdwDisposition,
            IntPtr hTransaction,
            IntPtr pExtendedParameter);

        [DllFunction(Advapi32DllName, RegCreateKeyTransactedFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegCreateKeyTransacted_Delegate(
            UIntPtr hKey,
            String lpSubKey,
            UInt32 Reserved,
            String lpClass,
            RegOption dwOptions,
            KeySecurity samDesired,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            /*ref IntPtr*/ IntPtr phkResult,
            /*ref RegKeyDisposition*/ IntPtr lpdwDisposition,
            IntPtr hTransaction,
            IntPtr pExtendedParameter);

        #endregion

        #region RegDeleteKey function

        internal const String RegDeleteKeyFuncName = "RegDeleteKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegDeleteKey(
            IntPtr hKey,
            String lpSubKey);

        [DllFunction(Advapi32DllName, RegDeleteKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegDeleteKey_Delegate(
            IntPtr hKey,
            String lpSubKey);

        #endregion

        #region RegDeleteKeyEx function

        internal const String RegDeleteKeyExFuncName = "RegDeleteKeyExW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegDeleteKeyEx(
            IntPtr hKey,
            string lpSubKey,
            RegWow64Options samDesired,
            int Reserved);

        [DllFunction(Advapi32DllName, RegDeleteKeyExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegDeleteKeyEx_Delegate(
            IntPtr hKey,
            string lpSubKey,
            RegWow64Options samDesired,
            int Reserved);

        #endregion

        #region RegDeleteKeyTransacted function

        internal const String RegDeleteKeyTransactedFuncName = "RegDeleteKeyTransactedW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegDeleteKeyTransacted(
            UIntPtr hKey,
            String lpSubKey,
            KeySecurity samDesired,
            UInt32 Reserved,
            IntPtr Transaction,
            IntPtr pExtendedParemeter);

        [DllFunction(Advapi32DllName, RegDeleteKeyTransactedFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegDeleteKeyTransacted_Delegate(
            UIntPtr hKey,
            String lpSubKey,
            KeySecurity samDesired,
            UInt32 Reserved,
            IntPtr Transaction,
            IntPtr pExtendedParemeter);

        #endregion

        #region RegDeleteKeyValue function

        internal const String RegDeleteKeyValueFuncName = "RegDeleteKeyValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegDeleteKeyValue(
            IntPtr hKey,
            string lpSubKey,
            string lpValueName);

        [DllFunction(Advapi32DllName, RegDeleteKeyValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegDeleteKeyValue_Delegate(
            IntPtr hKey,
            string lpSubKey,
            string lpValueName);

        #endregion

        #region RegDeleteTree function

        internal const String RegDeleteTreeFuncName = "RegDeleteTreeW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegDeleteTree(
            IntPtr hKey,
            String lpSubKey);

        [DllFunction(Advapi32DllName, RegDeleteTreeFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegDeleteTree_Delegate(
            IntPtr hKey,
            String lpSubKey);

        #endregion

        #region RegDeleteValue function

        internal const String RegDeleteValueFuncName = "RegDeleteValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegDeleteValue(
            IntPtr hKey,
            string lpValueName);

        [DllFunction(Advapi32DllName, RegDeleteValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegDeleteValue_Delegate(
            IntPtr hKey,
            string lpValueName);

        #endregion

        #region RegDisableReflectionKey function

        internal const String RegDisableReflectionKeyFuncName = "RegDisableReflectionKey";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegDisableReflectionKey(UIntPtr hBase);

        [DllFunction(Advapi32DllName, RegDisableReflectionKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegDisableReflectionKey_Delegate(UIntPtr hBase);

        #endregion

        #region RegEnableReflectionKey function

        internal const String RegEnableReflectionKeyFuncName = "RegEnableReflectionKey";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegEnableReflectionKey(UIntPtr hBase);

        [DllFunction(Advapi32DllName, RegEnableReflectionKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegEnableReflectionKey_Delegate(UIntPtr hBase);

        #endregion

        #region RegEnumKey function

        internal const String RegEnumKeyFuncName = "RegEnumKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegEnumKey(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            uint cchName);

        [DllFunction(Advapi32DllName, RegEnumKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegEnumKey_Delegate(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            uint cchName);

        #endregion

        #region RegEnumKeyEx function

        internal const String RegEnumKeyExFuncName = "RegEnumKeyExW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegEnumKeyEx(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref FILETIME*/ IntPtr lpftLastWriteTime);

        [DllFunction(Advapi32DllName, RegEnumKeyExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegEnumKeyEx_Delegate(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref FILETIME*/ IntPtr lpftLastWriteTime);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegEnumKeyExA(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref FILETIME*/ IntPtr lpftLastWriteTime);

        #endregion

        #region RegEnumValue function

        internal const String RegEnumValueFuncName = "RegEnumValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegEnumValue(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            IntPtr lpReserved,
            /*ref RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData);

        [DllFunction(Advapi32DllName, RegEnumValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegEnumValue_Delegate(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            IntPtr lpReserved,
            /*ref RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegEnumValueA(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            IntPtr lpReserved,
            /*ref RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData);

        #endregion

        #region RegFlushKey function

        internal const String RegFlushKeyFuncName = "RegFlushKey";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegFlushKey(
            UIntPtr hKey);

        [DllFunction(Advapi32DllName, RegFlushKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegFlushKey_Delegate(
            UIntPtr hKey);

        #endregion

        #region RegGetKeySecurity function

        internal const String RegGetKeySecurityFuncName = "RegGetKeySecurity";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegGetKeySecurity(
            IntPtr hKey,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr pSecurityDescriptor,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor);

        [DllFunction(Advapi32DllName, RegGetKeySecurityFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegGetKeySecurity_Delegate(
            IntPtr hKey,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr pSecurityDescriptor,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor);

        #endregion

        #region RegGetValue function

        internal enum RegRestrictionFlags : uint
        {
            RRF_RT_REG_SZ = 2,
            RRF_RT_ANY = 0xFFFF
        }

        internal const String RegGetValueFuncName = "RegGetValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegGetValue(
            IntPtr hKey,
            String lpSubKey,
            String lpValue,
            RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData);

        [DllFunction(Advapi32DllName, RegGetValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegGetValue_Delegate(
            IntPtr hKey,
            String lpSubKey,
            String lpValue,
            RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData);

        #endregion

        #region RegLoadKey function

        internal const String RegLoadKeyFuncName = "RegLoadKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegLoadKey(
            UIntPtr hKey,
            String lpSubKey,
            String lpFile);

        [DllFunction(Advapi32DllName, RegLoadKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegLoadKey_Delegate(
            UIntPtr hKey,
            String lpSubKey,
            String lpFile);

        #endregion

        #region RegNotifyChangeKeyValue

        internal const String RegNotifyChangeKeyValueFuncName = "RegNotifyChangeKeyValue";

        [Flags]
        internal enum REG_NOTIFY_CHANGE : uint
        {
           /// <summary>
           /// Notify the caller if a subkey is added or deleted
           /// </summary>
             NAME       = 0x1,
           /// <summary>
           /// Notify the caller of changes to the attributes of the key,
           /// such as the security descriptor information
           /// </summary>
             ATTRIBUTES = 0x2,
           /// <summary>
           /// Notify the caller of changes to a value of the key. This can
           /// include adding or deleting a value, or changing an existing value
           /// </summary>
             LAST_SET   = 0x4,
           /// <summary>
           /// Notify the caller of changes to the security descriptor of the key
           /// </summary>
             SECURITY   = 0x8
        }

        [DllImport(Advapi32DllName)]
        internal static extern int RegNotifyChangeKeyValue(
            IntPtr        hKey,
            bool          watchSubtree,
            REG_NOTIFY_CHANGE notifyFilter,
            IntPtr        hEvent,
            bool          asynchronous);

        [DllFunction(Advapi32DllName, RegNotifyChangeKeyValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegNotifyChangeKeyValue_Delegate(
            IntPtr hKey,
            bool watchSubtree,
            REG_NOTIFY_CHANGE notifyFilter,
            IntPtr hEvent,
            bool asynchronous);

        #endregion

        #region RegOpenCurrentUser function

        internal const String RegOpenCurrentUserFuncName = "RegOpenCurrentUser";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegOpenCurrentUser(
            KeySecurity samDesired,
            out IntPtr phkResult);

        [DllFunction(Advapi32DllName, RegOpenCurrentUserFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegOpenCurrentUser_Delegate(
            KeySecurity samDesired,
            out IntPtr phkResult);

        #endregion

        #region RegOpenKey function

        internal const String RegOpenKeyFuncName = "RegOpenKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegOpenKey(
            IntPtr hKey,
            String lpSubKey,
            /*ref IntPtr*/ out IntPtr phkResult);

        [DllFunction(Advapi32DllName, RegOpenKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegOpenKey_Delegate(
            IntPtr hKey,
            String lpSubKey,
            /*ref IntPtr*/ out IntPtr phkResult);

        #endregion

        #region RegOpenKeyA function

        internal const String RegOpenKeyAFuncName = "RegOpenKeyA";

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegOpenKeyA(
            IntPtr hKey,
            String lpSubKey,
            /*ref IntPtr*/ out IntPtr phkResult);

        #endregion

        #region RegOpenKeyEx function

        internal const String RegOpenKeyExFuncName = "RegOpenKeyExW";

        internal enum RegWow64Options : int
        {
            None = 0,
            KEY_WOW64_64KEY = 0x0100,
            KEY_WOW64_32KEY = 0x0200
        }

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegOpenKeyEx(
            IntPtr hKey,
            String lpSubKey,
            int ulOptions,
            KeySecurity samDesired,
            out IntPtr phkResult);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegOpenKeyExA(
            IntPtr hKey,
            String lpSubKey,
            int ulOptions,
            KeySecurity samDesired,
            out IntPtr phkResult);

        [DllFunction(Advapi32DllName, RegOpenKeyExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegOpenKeyEx_Delegate(
            IntPtr hKey,
            String lpSubKey,
            int ulOptions,
            KeySecurity samDesired,
            out IntPtr phkResult);

        #endregion

        #region RegOpenKeyTransacted function

        internal const String RegOpenKeyTransactedFuncName = "RegOpenKeyTransactedW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegOpenKeyTransacted(
            UIntPtr hKey,
            String lpSubKey,
            UInt32 ulOptions,
            KeySecurity samDesired,
            /*ref IntPtr*/ IntPtr phkResult,
            IntPtr hTransaction,
            IntPtr ExtendedParameter);

        [DllFunction(Advapi32DllName, RegOpenKeyTransactedFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegOpenKeyTransacted_Delegate(
            UIntPtr hKey,
            String lpSubKey,
            UInt32 ulOptions,
            KeySecurity samDesired,
            /*ref IntPtr*/ IntPtr phkResult,
            IntPtr hTransaction,
            IntPtr ExtendedParameter);

        #endregion

        #region RegOpenUserClassesRoot function

        internal const String RegOpenUserClassesRootFuncName = "RegOpenUserClassesRoot";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegOpenUserClassesRoot(
            IntPtr hToken,
            UInt32 dwOptions,
            KeySecurity samDesired,
            /*ref IntPtr*/ out IntPtr phkResult);

        [DllFunction(Advapi32DllName, RegOpenUserClassesRootFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegOpenUserClassesRoot_Delegate(
            IntPtr hToken,
            UInt32 dwOptions,
            KeySecurity samDesired,
            /*ref IntPtr*/ out IntPtr phkResult);

        #endregion

        #region RegOverridePredefKey function

        internal const String RegOverridePredefKeyFuncName = "RegOverridePredefKey";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegOverridePredefKey(
            IntPtr hKey,
            IntPtr hNewHKey);

        [DllFunction(Advapi32DllName, RegOverridePredefKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegOverridePredefKey_Delegate(
            IntPtr hKey,
            IntPtr hNewHKey);

        #endregion

        #region RegQueryInfoKey function

        internal const String RegQueryInfoKeyFuncName = "RegQueryInfoKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegQueryInfoKey(
            IntPtr hKey,
            /*out StringBuilder*/IntPtr lpClass,
            /*ref */IntPtr lpcClass,
            IntPtr lpReserved,
            /*out */IntPtr lpcSubKeys,
            /*out */IntPtr lpcbMaxSubKeyLen,
            /*out */IntPtr lpcbMaxClassLen,
            /*out */IntPtr lpcValues,
            /*out */IntPtr lpcbMaxValueNameLen,
            /*out */IntPtr lpcbMaxValueLen,
            /*out */IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime);

        [DllFunction(Advapi32DllName, RegQueryInfoKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegQueryInfoKey_Delegate(
            IntPtr hKey,
            /*out StringBuilder*/IntPtr lpClass,
            /*ref */IntPtr lpcClass,
            IntPtr lpReserved,
            /*out */IntPtr lpcSubKeys,
            /*out */IntPtr lpcbMaxSubKeyLen,
            /*out */IntPtr lpcbMaxClassLen,
            /*out */IntPtr lpcValues,
            /*out */IntPtr lpcbMaxValueNameLen,
            /*out */IntPtr lpcbMaxValueLen,
            /*out */IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegQueryInfoKeyA(
            IntPtr hKey,
            /*out StringBuilder*/IntPtr lpClass,
            /*ref */IntPtr lpcClass,
            IntPtr lpReserved,
            /*out */IntPtr lpcSubKeys,
            /*out */IntPtr lpcbMaxSubKeyLen,
            /*out */IntPtr lpcbMaxClassLen,
            /*out */IntPtr lpcValues,
            /*out */IntPtr lpcbMaxValueNameLen,
            /*out */IntPtr lpcbMaxValueLen,
            /*out */IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime);

        #endregion

        #region RegQueryMultipleValues function

        internal const String RegQueryMultipleValuesFuncName = "RegQueryMultipleValuesW";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct VALENT
        {
            String ve_valuename;  
            UInt32 ve_valuelen;  
            UIntPtr ve_valueptr;  
            UInt32 ve_type;
        }

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern int RegQueryMultipleValues(
            IntPtr hKey,
            //This is [in,out] array of VALENT structures.
            IntPtr val_list,
            UInt32 num_vals,
            IntPtr lpValueBuf,
            /*ref UInt32*/ IntPtr ldwTotsize);

        [DllFunction(Advapi32DllName, RegQueryMultipleValuesFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegQueryMultipleValues_Delegate(
            IntPtr hKey,
            //This is [in,out] array of VALENT structures.
            IntPtr val_list,
            UInt32 num_vals,
            IntPtr lpValueBuf,
            /*ref UInt32*/ IntPtr ldwTotsize);

        #endregion

        #region RegQueryReflectionKey function

        internal const String RegQueryReflectionKeyFuncName = "RegQueryReflectionKey";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegQueryReflectionKey(
            IntPtr hBase,
            /*ref Boolean*/ IntPtr bIsReflectionDisabled);

        [DllFunction(Advapi32DllName, RegQueryReflectionKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegQueryReflectionKey_Delegate(
            IntPtr hBase,
            /*ref Boolean*/ IntPtr bIsReflectionDisabled);

        #endregion

        #region RegQueryValue function

        internal const String RegQueryValueFuncName = "RegQueryValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegQueryValue(
            IntPtr hKey,
            string lpSubKey,
            IntPtr lpData,
            IntPtr lpcbData);

        [DllFunction(Advapi32DllName, RegQueryValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegQueryValue_Delegate(
            IntPtr hKey,
            string lpSubKey,
            IntPtr lpData,
            IntPtr lpcbData);

        #endregion

        #region RegQueryValueEx function

        internal const String RegQueryValueExFuncName = "RegQueryValueExW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData);

        [DllFunction(Advapi32DllName, RegQueryValueExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegQueryValueEx_Delegate(
            IntPtr hKey,
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegQueryValueExA(
            IntPtr hKey,
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData);

        #endregion

        #region RegReplaceKey function

        internal const String RegReplaceKeyFuncName = "RegReplaceKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegReplaceKey(
            UIntPtr hKey,
            String lpSubKey,
            String lpNewFile,
            String lpOldFile);

        [DllFunction(Advapi32DllName, RegReplaceKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegReplaceKey_Delegate(
            UIntPtr hKey,
            String lpSubKey,
            String lpNewFile,
            String lpOldFile);

        #endregion

        #region RegRestoreKey function

        internal const String RegRestoreKeyFuncName = "RegRestoreKeyW";

        internal enum RegRestoreKeyFlags : uint
        {
            REG_FORCE_RESTORE = 0x00000008,
            REG_WHOLE_HIVE_VOLATILE = 0x00000001
        }

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegRestoreKey(
            UIntPtr hKey,
            String lpFile,
            RegRestoreKeyFlags dwFlags);

        [DllFunction(Advapi32DllName, RegRestoreKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegRestoreKey_Delegate(
            UIntPtr hKey,
            String lpFile,
            RegRestoreKeyFlags dwFlags);

        #endregion

        #region RegSaveKey function

        internal const String RegSaveKeyFuncName = "RegSaveKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegSaveKey(
            UIntPtr hKey,
            String lpFile,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes);

        [DllFunction(Advapi32DllName, RegSaveKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegSaveKey_Delegate(
            UIntPtr hKey,
            String lpFile,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes);

        #endregion

        #region RegSaveKeyEx function

        internal const String RegSaveKeyExFuncName = "RegSaveKeyExW";

        internal enum RegSaveKeyExFlags : uint
        {
            REG_STANDARD_FORMAT = 1,
            REG_LATEST_FORMAT   = 2,
            REG_NO_COMPRESSION  = 4
        }

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegSaveKeyEx(
            UIntPtr hKey,
            String lpFile,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            RegSaveKeyExFlags Flags);

        [DllFunction(Advapi32DllName, RegSaveKeyExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegSaveKeyEx_Delegate(
            UIntPtr hKey,
            String lpFile,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            RegSaveKeyExFlags Flags);

        #endregion
        
        #region RegSetKeyValue function

        internal const String RegSetKeyValueFuncName = "RegSetKeyValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegSetKeyValue(
            IntPtr hKey,
            String lpSubKey,
            String lpValueName,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        [DllFunction(Advapi32DllName, RegSetKeyValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegSetKeyValue_Delegate(
            IntPtr hKey,
            String lpSubKey,
            String lpValueName,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegSetKeyValueA(
            IntPtr hKey,
            String lpSubKey,
            String lpValueName,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        #endregion

        #region RegSetKeySecurity function

        internal const String RegSetKeySecurityFuncName = "RegSetKeySecurity";

        [DllImport(Advapi32DllName)]
        internal static extern Int32 RegSetKeySecurity(
            UIntPtr hKey,
            SECURITY_INFORMATION SecurityInformation,
            /*ref IntPtr*/ IntPtr pSecurityDescriptor);

        [DllFunction(Advapi32DllName, RegSetKeySecurityFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate Int32 RegSetKeySecurity_Delegate(
            UIntPtr hKey,
            SECURITY_INFORMATION SecurityInformation,
            /*ref IntPtr*/ IntPtr pSecurityDescriptor);

        #endregion

        #region RegSetValue function

        internal const String RegSetValueFuncName = "RegSetValueW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegSetValue(
            IntPtr hKey,
            String lpSubKey,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        [DllFunction(Advapi32DllName, RegSetValueFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegSetValue_Delegate(
            IntPtr hKey,
            String lpSubKey,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        #endregion

        #region RegSetValueEx function

        internal const String RegSetValueExFuncName = "RegSetValueExW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegSetValueEx(
            IntPtr hKey,
            String lpValueName,
            int Reserved,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        [DllFunction(Advapi32DllName, RegSetValueExFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegSetValueEx_Delegate(
            IntPtr hKey,
            String lpValueName,
            int Reserved,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        [DllImport(Advapi32DllName, CharSet = CharSet.Ansi)]
        internal static extern Int32 RegSetValueExA(
            IntPtr hKey,
            String lpValueName,
            int Reserved,
            RegValueType dwType,
            IntPtr lpData,
            int cbData);

        #endregion

        #region RegUnLoadKey function

        internal const String RegUnLoadKeyFuncName = "RegUnLoadKeyW";

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 RegUnLoadKey(
            UIntPtr hKey,
            String lpSubKey);

        [DllFunction(Advapi32DllName, RegUnLoadKeyFuncName, CATEGORY_REGISTRY)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        internal delegate Int32 RegUnLoadKey_Delegate(
            UIntPtr hKey,
            String lpSubKey);

        #endregion

        #endregion

        #region Process, Thread and Library Management API

        #region CreateProcess function

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            internal Int32 cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal Int32 dwX;
            internal Int32 dwY;
            internal Int32 dwXSize;
            internal Int32 dwYSize;
            internal Int32 dwXCountChars;
            internal Int32 dwYCountChars;
            internal Int32 dwFillAttribute;
            internal Int32 dwFlags;
            internal Int16 wShowWindow;
            internal Int16 cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal int dwProcessId;
            internal int dwThreadId;
        }

        internal enum ProcessCreationFlags : uint
        {
            CREATE_SUSPENDED = 0x00000004
        }

        [DllImport("kernel32.dll")]
        internal static extern bool CreateProcess(string lpApplicationName,
           string lpCommandLine,
           /*ref SECURITY_ATTRIBUTES*/ IntPtr lpProcessAttributes,
           /*ref SECURITY_ATTRIBUTES*/ IntPtr lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
           [In] ref STARTUPINFO lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation);

        #endregion

        #region CreateThread

        [UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.StdCall)]
        internal delegate void StartThread(IntPtr param);

        [DllImport(Kernel32DllName, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CreateThread(
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                StartThread lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                out uint lpThreadId);
        #endregion

        #region WaitForSingleObject

        internal const uint INFINITE = 0xFFFFFFFF;

        [DllImport(Kernel32DllName, SetLastError=true)]
        internal static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        #endregion

        #region ResumeThread function
        [DllImport("kernel32.dll")]
        internal static extern uint ResumeThread(IntPtr hThread);
        #endregion

        #region OpenThread function

        internal enum ThreadAccessRights : uint
        {
            THREAD_SUSPEND_RESUME = 0x00000002
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(
            ThreadAccessRights dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwThreadId);
        #endregion

        #region DuplicateHandle function

        [Flags]
        internal enum DuplicateOptions : uint
        {
            DUPLICATE_CLOSE_SOURCE = (0x00000001),// Closes the source handle. This occurs regardless of any error status returned.
            DUPLICATE_SAME_ACCESS = (0x00000002), //Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);
        #endregion

        #region SetEvent function
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetEvent(IntPtr hEvent);
        #endregion

        #region GetExitCodeProcess function

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        #endregion

        #region ExitProcess function

        internal const string ExitProcessFuncName = "ExitProcess";

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern void ExitProcess(uint exitCode);

        [DllFunction(Kernel32DllName, ExitProcessFuncName, ExitProcessFuncName)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate void ExitProcess_Delegate(uint exitCode);

        #endregion

        #region LoadLibrary function

        internal const String LoadLibraryFuncName = "LoadLibraryW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(String lpFileName);

        #endregion

        #region LoadLibraryEx function

        [Flags]
        internal enum LoadLibraryExFlags : uint
        {
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 0x00000080,
        }

        internal const String LoadLibraryExFuncName = "LoadLibraryExW";

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibraryEx(String lpFileName, IntPtr hFile, LoadLibraryExFlags dwFlags);

        [DllFunction(Kernel32DllName, LoadLibraryExFuncName, CATEGORY_FILE_ACCESS)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr LoadLibraryEx_Delegate(String lpFileName, IntPtr hFile, LoadLibraryExFlags dwFlags);

        #endregion

        #region FreeLibrary function

        [DllImport(Kernel32DllName, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FreeLibrary(IntPtr hModule);

        #endregion

        #endregion

        #region Windows management API

        #region PostMessage function

        internal const string PostMessageFuncName = "PostMessageW";

        [DllImport(User32DllName, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllFunction(User32DllName, PostMessageFuncName, "User32")]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool PostMessage_Delegate(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        #endregion

        #region DestroyWindow function

        internal const string DestroyWindowFuncName = "DestroyWindow";

        [DllImport(User32DllName, CharSet = CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DestroyWindow(IntPtr hwnd);

        [DllFunction(User32DllName, DestroyWindowFuncName, "User32")]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool DestroyWindow_Delegate(IntPtr hwnd);

        #endregion

        #endregion

        //Helper API functions are used just by Helper class and can be removed from 
        //the code if Helper class will be remvoed.
        #region Helper API functions

        internal const Int32 MAX_PATH = 260;

        internal enum FileMapProtection : uint
        {
            PAGE_READONLY = 0x02
        }

        internal enum FileMapAccess : uint 
        {
            FILE_MAP_READ = 0x04,
        }

        internal enum Error : int
        {
            ERROR_SUCCESS = 0,
            ERROR_FILE_NOT_FOUND = 2,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INVALID_HANDLE = 6,
            ERROR_NOT_ENOUGH_MEMORY = 8,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_MORE_DATA = 234,
            ERROR_NO_MORE_ITEMS = 259,
            ERROR_FILE_INVALID = 1006
        }

        internal enum Status : int
        {
            STATUS_SUCCESS = 0,
            STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023)
        }

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFileMapping(
           IntPtr hFile,
           IntPtr lpFileMappingAttributes,
           FileMapProtection flProtect,
           UInt32 dwMaximumSizeHigh,
           UInt32 dwMaximumSizeLow,
           String lpName);

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern IntPtr MapViewOfFile(
               IntPtr hFileMappingObject,
               FileMapAccess dwDesiredAccess,
               uint dwFileOffsetHigh,
               uint dwFileOffsetLow,
               uint dwNumberOfBytesToMap);

        [DllImport(PsapiDllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern UInt32 GetMappedFileName(
           IntPtr hProcess,
           IntPtr lpv,
           StringBuilder lpFileName,
           UInt32 nSize);

        [DllImport(Kernel32DllName, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool isWow64);
        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();
        [DllImport(Kernel32DllName, CharSet = CharSet.Auto)]
        internal static extern IntPtr GetModuleHandle(string moduleName);
        [DllImport(Kernel32DllName, CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string methodName);

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern UInt32 GetLogicalDriveStrings(UInt32 nBufferLength,
	        Char[] lpBuffer);

        [DllImport(Kernel32DllName, SetLastError = true)]
        internal static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        [DllImport(Kernel32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern UInt32 QueryDosDevice(String lpDeviceName, StringBuilder lpTargetPath, UInt32 ucchMax);

        [StructLayout(LayoutKind.Sequential)]
        internal struct QUERY_SERVICE_CONFIG 
        {
            internal UInt32 dwServiceType;
            internal UInt32 dwStartType;
            internal UInt32 dwErrorControl;
            internal String lpBinaryPathName;
            internal String lpLoadOrderGroup;
            internal UInt32 dwTagId;
            internal String lpDependencies;
            internal String lpServiceStartName;
            internal String lpDisplayName;
        }

        [DllImport(Advapi32DllName, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern Boolean QueryServiceConfig(IntPtr hService, ref QUERY_SERVICE_CONFIG lpServiceConfig, 
            UInt32 cbBufSize, ref UInt32 pcbBytesNeeded);

        [DllImport(Kernel32DllName)]
        internal static extern void SetLastError(uint dwErrCode);

        [DllImport(Kernel32DllName)]
        internal static extern uint GetLastError();

        internal enum TokenSecurity : uint
        {
            TOKEN_QUERY = 8
        }

        [DllImport(Advapi32DllName, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(IntPtr hProcess,
            TokenSecurity desiredAccess, out IntPtr hToken);

        #region SetUnhandledExceptionFilter

        internal enum EXCEPTION_RESULT : int
        {
            EXCEPTION_CONTINUE_SEARCH = 0,
            EXCEPTION_EXECUTE_HANDLER = 1
        }

        internal const string SetUnhandledExceptionFilterFuncName = "SetUnhandledExceptionFilter";

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int UnhandledExceptionFilter_Delegate(IntPtr ExceptionInfo);

        [DllImport(Kernel32DllName)]
        internal static extern UnhandledExceptionFilter_Delegate SetUnhandledExceptionFilter(
            UnhandledExceptionFilter_Delegate lpTopLevelExceptionFilter);

        [DllFunction(Kernel32DllName, SetUnhandledExceptionFilterFuncName, SetUnhandledExceptionFilterFuncName)]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate UnhandledExceptionFilter_Delegate SetUnhandledExceptionFilter_Delegate(
            UnhandledExceptionFilter_Delegate lpTopLevelExceptionFilter);

        #endregion

        #endregion

    }
}
