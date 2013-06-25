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
    internal struct KeyNameAndClass
    {
        internal string Name;
        internal string Class;
    }

    internal static class VirtualKeyExtensions
    {
        internal static KeyNameAndClass[] GetSubKeysInformation(this VirtualKey key, KeyInfo keyInfo)
        {
            uint maxKeyNameLength = keyInfo.MaxSubKeyLength;
            uint maxClassLength = keyInfo.MaxClassLength;

            uint subKeysNumber = keyInfo.SubKeysNumber;

            if (subKeysNumber == 0)
            {
                return new KeyNameAndClass[0];
            }

            var result = new KeyNameAndClass[subKeysNumber];

            using (HGlobalPtr lpName = new HGlobalPtr((maxKeyNameLength + 1) * sizeof(char)),
                              lpcName = new HGlobalPtr(sizeof(int)),
                              lpReserved = new HGlobalPtr(IntPtr.Zero),
                              lpClass = new HGlobalPtr((maxClassLength + 1) * sizeof(char)),
                              lpcClass = new HGlobalPtr(sizeof(int)),
                              lpftLastWriteTime = new HGlobalPtr(IntPtr.Zero))
            {
                for (uint i = 0; i < subKeysNumber; ++i)
                {
                    Marshal.WriteInt32(lpcName.Ptr, unchecked((int)maxKeyNameLength) + 1);
                    Marshal.WriteInt32(lpcClass.Ptr, unchecked((int)maxClassLength) + 1);

                    key.EnumKey(
                        i,
                        lpName.Ptr,
                        lpcName.Ptr,
                        lpReserved.Ptr,
                        lpClass.Ptr,
                        lpcClass.Ptr,
                        lpftLastWriteTime.Ptr);

                    KeyNameAndClass currentInfo;

                    int currentNameLength = Marshal.ReadInt32(lpcName.Ptr);
                    int currentClassLength = Marshal.ReadInt32(lpcClass.Ptr);
                    currentInfo.Name = Marshal.PtrToStringUni(lpName.Ptr, currentNameLength);
                    currentInfo.Class = Marshal.PtrToStringUni(lpClass.Ptr, currentClassLength);

                    result[i] = currentInfo;
                }
            }

            Array.Sort(result, (left, right) => String.CompareOrdinal(left.Name, right.Name));
            return result;
        }

        internal static void QueryMultipleValues(
            this VirtualKey key,
            IntPtr val_list,
            UInt32 num_vals,
            IntPtr lpValueBuf,
            IntPtr ldwTotsize)
        {
            // TODO: although the reason RegQueryMultipleValues function exists
            // is to allow atomic reading of multiple values of a key,
            // the current implementation reads them non-atomically, so this is a
            // possible subject to change in the future
            int totalSize = 0;
            if (ldwTotsize != IntPtr.Zero) totalSize = Marshal.ReadInt32(ldwTotsize);
            int usedSize = 0;
            Int64 PTR_SIZE = Marshal.SizeOf(typeof(IntPtr));

            for (uint i = 0; i < num_vals; ++i)
            {
                Int64 pVal = (Int64)val_list + 8 * i + 2 * PTR_SIZE * i;

                IntPtr lpValueName = Marshal.ReadIntPtr((IntPtr)pVal);
                string valueName = DataTransformer.PtrToString(lpValueName);

                IntPtr pcbData = (IntPtr)(pVal + PTR_SIZE);
                Marshal.WriteInt32(pcbData, Math.Max(0, totalSize - usedSize));

                IntPtr lpData = (lpValueBuf == IntPtr.Zero || usedSize > totalSize) ?
                                    IntPtr.Zero :
                                    (IntPtr)((Int64)lpValueBuf + usedSize);
                Marshal.WriteIntPtr((IntPtr)(pVal + 4 + PTR_SIZE), lpData);

                IntPtr lpType = (IntPtr)(pVal + 4 + 2 * PTR_SIZE);
                try
                {
                    key.QueryValue(valueName, IntPtr.Zero, lpType, lpData, pcbData);
                }
                catch (Win32Exception ex)
                {
                    if (ex.ErrorCode != (int)Win32Api.Error.ERROR_MORE_DATA)
                    {
                        throw;
                    }
                }
                int valueSize = Marshal.ReadInt32(pcbData);
                usedSize += valueSize;
            }
            if (ldwTotsize != IntPtr.Zero) Marshal.WriteInt32(ldwTotsize, usedSize);
            if (usedSize > totalSize)
            {
                throw Win32Exception.Create((int)Win32Api.Error.ERROR_MORE_DATA);
            }
        }
    }
}