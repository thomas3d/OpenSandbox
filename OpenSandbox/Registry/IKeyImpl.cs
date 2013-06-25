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
    internal enum KeyDisposition
    {
        WINDOWS_REG = 0,
        BASE_HIVE = 1,
        DIFF_HIVE = 2
    }

    internal interface IKey
    {
        void Close();

        void SetValue(
            string lpValueName,
            Win32Api.RegValueType dwType,
            IntPtr lpData,
            int cbData);

        void Delete();

        void DeleteValue(string lpValueName);

        void EnumKey(
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref Win32Api.FILETIME*/ IntPtr lpftLastWriteTime);

        void EnumValue(
            uint dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            IntPtr lpReserved,
            /*ref Win32Api.RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData);

        void QueryInfo(
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
    }

    internal interface IKeyImplHandler
    {
        bool Handle(WindowsKey key);
        bool Handle(OffRegKey key);
    }

    internal interface IKeyImpl : IKey
    {
        bool TryGetValue(
            string lpValue,
            Win32Api.RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData);

        bool TryQueryValue(
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData);

        KeyDisposition GetDisposition();
        KeySecurity GetAccessMode();
        bool TryApply(IKeyImplHandler handler);
    }

    internal struct KeyInfo
    {
        internal string Class;
        internal uint SubKeysNumber;
        internal uint MaxSubKeyLength;
        internal uint MaxClassLength;
        internal uint ValuesNumber;
        internal uint MaxValueNameLength;
        internal uint MaxValueLength;
        internal uint SecurityDescriptorLength;
        internal Win32Api.FILETIME LastWriteTime;
    }

    internal static class IKeyExtensions
    {
        internal static KeyInfo QueryInfo(this IKey key)
        {
            using (HGlobalPtr lpcClass = new HGlobalPtr(Marshal.SizeOf(typeof(int))))
            {
                Marshal.WriteInt32(lpcClass.Ptr, 0);
                try
                {
                    key.QueryInfo(IntPtr.Zero, lpcClass.Ptr, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero);
                }
                catch (Win32Exception ex)
                {
                    if (ex.ErrorCode != (int)Win32Api.Error.ERROR_MORE_DATA)
                    {
                        throw;
                    }
                }
                int cClass = Marshal.ReadInt32(lpcClass.Ptr) + 1;
                Marshal.WriteInt32(lpcClass.Ptr, cClass);
                using (HGlobalPtr lpClass = new HGlobalPtr(cClass * sizeof(char)),
                                  lpReserved = new HGlobalPtr(IntPtr.Zero),
                                  lpcSubKeys = new HGlobalPtr(sizeof(int)),
                                  lpcMaxSubKeyLen = new HGlobalPtr(sizeof(int)),
                                  lpcMaxClassLen = new HGlobalPtr(sizeof(int)),
                                  lpcValues = new HGlobalPtr(sizeof(int)),
                                  lpcMaxValueNameLen = new HGlobalPtr(sizeof(int)),
                                  lpcMaxValueLen = new HGlobalPtr(sizeof(int)),
                                  lpcSecurityDescriptor = new HGlobalPtr(sizeof(int)),
                                  lpftLastWriteTime = new HGlobalPtr(2 * sizeof(int)))
                {
                    key.QueryInfo(
                        lpClass.Ptr,
                        lpcClass.Ptr,
                        lpReserved.Ptr,
                        lpcSubKeys.Ptr,
                        lpcMaxSubKeyLen.Ptr,
                        lpcMaxClassLen.Ptr,
                        lpcValues.Ptr,
                        lpcMaxValueNameLen.Ptr,
                        lpcMaxValueLen.Ptr,
                        lpcSecurityDescriptor.Ptr,
                        lpftLastWriteTime.Ptr);

                    int classLength = Marshal.ReadInt32(lpcClass.Ptr);
                    Win32Api.FILETIME lastWriteTime =
                        (Win32Api.FILETIME)Marshal.PtrToStructure(lpftLastWriteTime.Ptr,
                            typeof(Win32Api.FILETIME));

                    KeyInfo info;

                    info.Class = DataTransformer.PtrToString(lpClass.Ptr, classLength);
                    info.SubKeysNumber = unchecked((uint)Marshal.ReadInt32(lpcSubKeys.Ptr));
                    info.MaxSubKeyLength = unchecked((uint)Marshal.ReadInt32(lpcMaxSubKeyLen.Ptr));
                    info.MaxClassLength = unchecked((uint)Marshal.ReadInt32(lpcMaxClassLen.Ptr));
                    info.ValuesNumber = unchecked((uint)Marshal.ReadInt32(lpcValues.Ptr));
                    info.MaxValueNameLength = unchecked((uint)Marshal.ReadInt32(lpcMaxValueNameLen.Ptr));
                    info.MaxValueLength = unchecked((uint)Marshal.ReadInt32(lpcMaxValueLen.Ptr));
                    info.SecurityDescriptorLength = unchecked((uint)Marshal.ReadInt32(lpcSecurityDescriptor.Ptr));
                    info.LastWriteTime = lastWriteTime;

                    return info;
                }
            }
        }
    }
}
