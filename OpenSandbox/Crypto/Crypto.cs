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
using OpenSandbox.Logging;

namespace OpenSandbox.Crypto
{
    internal interface IReader
    {
        int Read(IntPtr pData, int cbData);
    }

    internal interface IWriter
    {
        int Write(IntPtr pData, int cbData);
    }

    internal interface ICryptoProvider
    {
        IReader CreateReader(IReader encrypted);
        IWriter CreateWriter(IWriter encrypted);
    }

    internal class PlainReader : IReader
    {
        private IReader encrypted_;

        internal PlainReader(IReader encrypted)
        {
            encrypted_ = encrypted;
        }

        public int Read(IntPtr pData, int cbData)
        {
            return encrypted_.Read(pData, cbData);
        }
    }

    internal class PlainWriter : IWriter
    {
        private IWriter encrypted_;

        internal PlainWriter(IWriter encrypted)
        {
            encrypted_ = encrypted;
        }

        public int Write(IntPtr pData, int cbData)
        {
            return encrypted_.Write(pData, cbData);
        }
    }

    internal class PlainCryptoProvider : ICryptoProvider
    {
        public IReader CreateReader(IReader encrypted)
        {
            return new PlainReader(encrypted);
        }

        public IWriter CreateWriter(IWriter encrypted)
        {
            return new PlainWriter(encrypted);
        }
    }

    internal class FileReaderWriter : IReader, IWriter
    {
        private IntPtr hFile_;

        internal FileReaderWriter(IntPtr hFile)
        {
            hFile_ = hFile;
        }

        public int Read(IntPtr pData, int cbData)
        {
            using (HGlobalPtr pcbData = new HGlobalPtr(sizeof(int)))
            {
                if (!Win32Api.ReadFile(hFile_, pData, unchecked((uint)cbData),
                    pcbData.Ptr, IntPtr.Zero))
                {
                    throw Win32Exception.Create(unchecked((int)Win32Api.GetLastError()));
                }
                return Marshal.ReadInt32(pcbData.Ptr);
            }
        }

        public int Write(IntPtr pData, int cbData)
        {
            using (HGlobalPtr pcbData = new HGlobalPtr(sizeof(int)))
            {
                if (!Win32Api.WriteFile(hFile_, pData, unchecked((uint)cbData),
                    pcbData.Ptr, IntPtr.Zero))
                {
                    throw Win32Exception.Create(unchecked((int)Win32Api.GetLastError()));
                }
                return Marshal.ReadInt32(pcbData.Ptr);
            }
        }
    }

    public class FileEncryptionLayer
    {
        private static Dictionary<string, ICryptoProvider> paths_ =
            new Dictionary<string, ICryptoProvider>(
                StringComparer.InvariantCultureIgnoreCase);

        private class Handler
        {
            internal string Path;
            internal IReader Reader;
            internal IWriter Writer;
        }
        private static Dictionary<IntPtr, Handler> handles_ =
            new Dictionary<IntPtr, Handler>();

        public static void AttachFile(string path, string keyString)
        {
            ICryptoProvider cryptoProvider;
            if (string.IsNullOrEmpty(keyString))
            {
                DebugLogger.WriteLine("Plain crypto provider for {0}.", path);
                cryptoProvider = new PlainCryptoProvider();
            }
            else
            {
                DebugLogger.WriteLine("AES crypto provider for {0}.", path);
                cryptoProvider = new AESProvider(keyString);
            }
            AttachFile(path, cryptoProvider);
        }

        internal static void AttachFile(string path, ICryptoProvider cryptoProvider)
        {
            lock (handles_)
            {
                paths_[Path.GetFullPath(path)] = cryptoProvider;
            }
        }

        internal static IntPtr CreateFile(
            String lpFileName,
            UInt32 dwDesiredAccess,
            Win32Api.FileShareMode dwShareMode,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            Win32Api.CreateFileCreationDisposition dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile)
        {
            IntPtr result = Win32Api.CreateFile(lpFileName, dwDesiredAccess, dwShareMode,
                lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
                hTemplateFile);
            try
            {
                if (result != Win32Api.INVALID_HANDLE_VALUE)
                {
                    string fullPath;
                    try
                    {
                        fullPath = Path.GetFullPath(lpFileName);
                    }
                    catch
                    {
                        // Path has a special form (either "\\?\" or file channel number "file:123" or smth else)
                        // so it is not crypto path
                        return result;
                    }
                    lock (handles_)
                    {
                        if (handles_.ContainsKey(result))
                        {
                            handles_.Remove(result);
                        }
                        if (paths_.ContainsKey(fullPath))
                        {
                            DebugLogger.WriteLine("CreateFile: {0} is crypto path", fullPath);
                            handles_.Add(result, new Handler { Path = fullPath });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine("CreateFile exception (=> native call result returned): " + ex);
            }
            return result;
        }

        private static IReader CheckHiveReader(IntPtr hObject)
        {
            try
            {
                lock (handles_)
                {
                    if (!handles_.ContainsKey(hObject)) return null;
                    Handler handler = handles_[hObject];
                    if (handler.Reader != null)
                        return handler.Reader;
                    if (handler.Writer != null)
                    {
                        DebugLogger.WriteLine("CheckHiveReader: Writer already created.");
                        // We don't support the case if both read and write
                        // operations are called against the file
                        return null;
                    }
                    handler.Reader = paths_[handler.Path].CreateReader(new FileReaderWriter(hObject));
//                    paths_.Remove(handler.Path);
                    return handler.Reader;
                }
            }
            catch { }
            return null;
        }

        private static IWriter CheckHiveWriter(IntPtr hObject)
        {
            try
            {
                lock (handles_)
                {
                    if (!handles_.ContainsKey(hObject)) return null;
                    Handler handler = handles_[hObject];
                    if (handler.Writer != null)
                        return handler.Writer;
                    if (handler.Reader != null)
                    {
                        DebugLogger.WriteLine("CheckHiveReader: Writer already created.");
                        // We don't support the case if both read and write
                        // operations are called against the file
                        return null;
                    }
                    handler.Writer = paths_[handler.Path].CreateWriter(new FileReaderWriter(hObject));
//                    paths_.Remove(handler.Path);
                    return handler.Writer;
                }
            }
            catch { }
            return null;
        }

        internal static bool ReadFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToRead,
            /*ref UInt32*/ IntPtr lpNumberOfBytesRead,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped)
        {
            IReader reader = CheckHiveReader(hFile);
            if (reader == null || lpOverlapped != IntPtr.Zero)
            {
                if (reader != null && lpOverlapped != IntPtr.Zero)
                {
                    DebugLogger.WriteLine(
                        "ReadFile: overlapped != null for the reghive handle," +
                        "can't deal with that, [hFile] {0}", hFile.ToString());
                }
                return Win32Api.ReadFile(hFile, lpBuffer, nNumberOfBytesToRead,
                    lpNumberOfBytesRead, lpOverlapped);
            }
            int cbData = unchecked((int)nNumberOfBytesToRead);
            int cbRead = 0;
            try
            {
                cbRead = reader.Read(lpBuffer, cbData);
            }
            finally
            {
                if (lpNumberOfBytesRead != IntPtr.Zero)
                    Marshal.WriteInt32(lpNumberOfBytesRead, cbRead);
            }
            return true;
        }

        internal static bool WriteFile(
            IntPtr hFile,
            IntPtr lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            /*ref UInt32*/ IntPtr lpNumberOfBytesWritten,
            /*ref OVERLAPPED*/ IntPtr lpOverlapped)
        {
            IWriter writer = CheckHiveWriter(hFile);
            if (writer == null || lpOverlapped != IntPtr.Zero)
            {
                if (writer != null && lpOverlapped != IntPtr.Zero)
                {
                    DebugLogger.WriteLine(
                        "WriteFile: overlapped != null for the reghive handle," +
                        "can't deal with that, [hFile] {0}", hFile.ToString());
                }
                return Win32Api.WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                    lpNumberOfBytesWritten, lpOverlapped);
            }
            int cbData = unchecked((int)nNumberOfBytesToWrite);
            int cbWritten = 0;
            try
            {
                cbWritten = writer.Write(lpBuffer, cbData);
            }
            finally
            {
                if (lpNumberOfBytesWritten != IntPtr.Zero)
                    Marshal.WriteInt32(lpNumberOfBytesWritten, cbWritten);
            }
            return true;
        }
    }
}
