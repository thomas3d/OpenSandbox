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
using System.Runtime.InteropServices;

namespace OpenSandbox.Registry
{
    internal static class NtQueryKeyExtension
    {
        internal static void NtQueryKey(this VirtualKey key, Win32Api.KeyInformationClass KeyInformationClass,
            IntPtr KeyInformation, uint Length, out uint ResultLength)
        {
            ResultLength = 0;
            NtQueryKey handler = new NtQueryKey(KeyInformationClass, KeyInformation, Length);
            try
            {
                key.ApplyReadOperation(null,
                    new KeySecurity(Win32Api.KeySecurity.KEY_QUERY_VALUE),
                    keyImpl => keyImpl.TryApply(handler));
            }
            finally
            {
                ResultLength = handler.ResultLength;
            }
        }
    }

    internal class NtQueryKey : IKeyImplHandler
    {
        private Win32Api.KeyInformationClass KeyInformationClass_;
        private IntPtr KeyInformation_;
        private uint Length_;
        private uint ResultLength_;

        internal uint ResultLength { get { return ResultLength_; } }

        internal NtQueryKey(Win32Api.KeyInformationClass KeyInformationClass,
            IntPtr KeyInformation, uint Length)
        {
            KeyInformationClass_ = KeyInformationClass;
            KeyInformation_ = KeyInformation;
            Length_ = Length;
        }

        public bool Handle(WindowsKey key)
        {
            if (!KeyIdentity.IsPredefined(key.Handle))
            {
                return Win32Exception.CheckIfFoundAndNoError(
                    Win32Api.NtQueryKey(key.Handle, KeyInformationClass_, KeyInformation_, Length_,
                    out ResultLength_));
            }
            // Predefined key handle values are valid only on the advapi32.dll level
            // on the ntdll.dll level we have to replace them with appropriate ntdll.dll handles
            IntPtr hNtKey = IntPtr.Zero;
            string objectName = KeyIdentity.GetSystemBasePath(key.Handle);
            Win32Api.UNICODE_STRING usObjectName = new Win32Api.UNICODE_STRING();
            usObjectName.Length = unchecked((ushort)(sizeof(char) * objectName.Length));
            usObjectName.MaximumLength = usObjectName.Length;
            using (HGlobalPtr pObjectNameBuffer = new HGlobalPtr(Marshal.StringToHGlobalUni(objectName)))
            {
                usObjectName.Buffer = pObjectNameBuffer.Ptr;
                using (HGlobalPtr pObjectName = new HGlobalPtr(Marshal.SizeOf(typeof(Win32Api.UNICODE_STRING))))
                {
                    Marshal.StructureToPtr(usObjectName, pObjectName.Ptr, false);
                    Win32Api.OBJECT_ATTRIBUTES oa = new Win32Api.OBJECT_ATTRIBUTES();
                    oa.Length = unchecked((uint)Marshal.SizeOf(typeof(Win32Api.OBJECT_ATTRIBUTES)));
                    oa.RootDirectory = IntPtr.Zero;
                    oa.ObjectName = pObjectName.Ptr;
                    oa.Attributes = (uint)Win32Api.ObjectAttributes.OBJ_CASE_INSENSITIVE;
                    oa.SecurityDescriptor = IntPtr.Zero;
                    oa.SecurityQualityOfService = IntPtr.Zero;
                    using (HGlobalPtr pOA = new HGlobalPtr(Marshal.SizeOf(typeof(Win32Api.OBJECT_ATTRIBUTES))))
                    {
                        Marshal.StructureToPtr(oa, pOA.Ptr, false);
                        if (!Win32Exception.CheckIfFoundAndNoError(
                            Win32Api.NtOpenKey(out hNtKey, (uint)Win32Api.KeySecurity.KEY_QUERY_VALUE, pOA.Ptr)))
                        {
                            return false;
                        }
                        try
                        {
                            return Win32Exception.CheckIfFoundAndNoError(
                                Win32Api.NtQueryKey(hNtKey, KeyInformationClass_, KeyInformation_, Length_,
                                out ResultLength_));
                        }
                        finally
                        {
                            Win32Api.NtClose(hNtKey);
                        }
                    }
                }
            }
        }

        public bool Handle(OffRegKey key)
        {
            // TODO: exceptions thrown from this function should use STATUS_* error codes set
            // instead of ERROR_*
            string name = key.Identity.GetSystemPath();
            KeyInfo info = key.QueryInfo();
            // TODO: either test the following error-prone code with offsets thoroughly
            // or replace it with safer alternative code
            int offset = 0;
            switch (KeyInformationClass_)
            {
                case Win32Api.KeyInformationClass.KeyBasicInformation:
                    ResultLength_ = unchecked((uint)(16 + sizeof(char) * name.Length));
                    if (Length_ < ResultLength_)
                    {
                        throw Win32Exception.Create((int)Win32Api.Status.STATUS_BUFFER_TOO_SMALL);
                    }
                    if (KeyInformation_ != IntPtr.Zero)
                    {
                        Marshal.StructureToPtr(info.LastWriteTime, KeyInformation_, false); offset += 8;
                        Marshal.WriteInt32(KeyInformation_, offset, 0); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, sizeof(char) * name.Length); offset += 4;
                        PInvokeHelper.CopyStringUni(name,
                            (IntPtr)((Int64)KeyInformation_ + offset), name.Length);
                    }
                    return true;
                case Win32Api.KeyInformationClass.KeyNodeInformation:
                    ResultLength_ = unchecked((uint)(24 + sizeof(char) * (name.Length + info.Class.Length)));
                    if (Length_ < ResultLength_)
                    {
                        throw Win32Exception.Create((int)Win32Api.Status.STATUS_BUFFER_TOO_SMALL);
                    }
                    if (KeyInformation_ != IntPtr.Zero)
                    {
                        // TODO: fill the parts of structures w/o strings using
                        // C# structures (until now I don't know solution for strings, but
                        // at least all other fields will be set carefully)
                        // do this throughout the function
                        Marshal.StructureToPtr(info.LastWriteTime, KeyInformation_, false); offset += 8;
                        Marshal.WriteInt32(KeyInformation_, offset, 0); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset,
                            24 + sizeof(char) * name.Length); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset,
                            sizeof(char) * info.Class.Length); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset,
                            sizeof(char) * name.Length); offset += 4;
                        PInvokeHelper.CopyStringUni(name,
                            (IntPtr)((Int64)KeyInformation_ + offset),
                            name.Length); offset += name.Length * sizeof(char);
                        PInvokeHelper.CopyStringUni(info.Class,
                            (IntPtr)((Int64)KeyInformation_ + offset),
                            info.Class.Length);
                    }
                    return true;
                case Win32Api.KeyInformationClass.KeyFullInformation:
                    ResultLength_ = unchecked((uint)(44 + sizeof(char) * (info.Class.Length)));
                    if (Length_ < ResultLength_)
                    {
                        throw Win32Exception.Create((int)Win32Api.Status.STATUS_BUFFER_TOO_SMALL);
                    }
                    if (KeyInformation_ != IntPtr.Zero)
                    {
                        Marshal.StructureToPtr(info.LastWriteTime, KeyInformation_, false); offset += 8;
                        Marshal.WriteInt32(KeyInformation_, offset, 0); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, 44); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset,
                            sizeof(char) * info.Class.Length); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.SubKeysNumber)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxSubKeyLength)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxClassLength)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.ValuesNumber)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxValueNameLength)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxValueLength)); offset += 4;
                        PInvokeHelper.CopyStringUni(info.Class,
                            (IntPtr)((Int64)KeyInformation_ + offset),
                            info.Class.Length);
                    }
                    return true;
                case Win32Api.KeyInformationClass.KeyNameInformation:
                    ResultLength_ = unchecked((uint)(4 + sizeof(char) * name.Length));
                    if (Length_ < ResultLength_)
                    {
                        throw Win32Exception.Create((int)Win32Api.Status.STATUS_BUFFER_TOO_SMALL);
                    }
                    if (KeyInformation_ != IntPtr.Zero)
                    {
                        Marshal.WriteInt32(KeyInformation_, sizeof(char) * name.Length); offset += 4;
                        PInvokeHelper.CopyStringUni(name,
                            (IntPtr)((Int64)KeyInformation_ + offset), name.Length);
                    }
                    return true;
                case Win32Api.KeyInformationClass.KeyCachedInformation:
                    ResultLength_ = 36;
                    if (Length_ < ResultLength_)
                    {
                        throw Win32Exception.Create((int)Win32Api.Status.STATUS_BUFFER_TOO_SMALL);
                    }
                    if (KeyInformation_ != IntPtr.Zero)
                    {
                        Marshal.StructureToPtr(info.LastWriteTime, KeyInformation_, false); offset += 8;
                        Marshal.WriteInt32(KeyInformation_, offset, 0); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.SubKeysNumber)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxSubKeyLength)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.ValuesNumber)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxValueNameLength)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, unchecked((int)info.MaxValueLength)); offset += 4;
                        Marshal.WriteInt32(KeyInformation_, offset, name.Length);
                    }
                    return true;
                case Win32Api.KeyInformationClass.KeyFlagsInformation:
                    // Reserved
                    break;
                case Win32Api.KeyInformationClass.KeyVirtualizationInformation:
                    // Not implemented
                    break;
                case Win32Api.KeyInformationClass.KeyHandleTagsInformation:
                    // Reserved
                    break;
            }
            return false;
        }
    }
}
