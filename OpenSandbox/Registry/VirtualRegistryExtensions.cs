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
using OpenSandbox;

namespace OpenSandbox.Registry
{
    internal static class VirtualRegistryExtensions
    {
        internal static void CopyValues(this VirtualRegistry virtualRegistry, VirtualKey sourceKey, KeyInfo sourceKeyInfo, VirtualKey destinationKey)
        {
            using (HGlobalPtr lpValueName = new HGlobalPtr((sourceKeyInfo.MaxValueNameLength + 1) * sizeof(char)),
                             lpcValueName = new HGlobalPtr(sizeof(int)),
                             lpReserved = new HGlobalPtr(IntPtr.Zero),
                             lpdwType = new HGlobalPtr(sizeof(int)),
                             lpvData = new HGlobalPtr(sourceKeyInfo.MaxValueLength),
                             lpcData = new HGlobalPtr(sizeof(int)))
            {
                for (uint i = 0; i < sourceKeyInfo.ValuesNumber; ++i)
                {
                    Marshal.WriteInt32(lpcValueName.Ptr, unchecked((int)sourceKeyInfo.MaxValueNameLength) + 1);
                    Marshal.WriteInt32(lpcData.Ptr, unchecked((int)sourceKeyInfo.MaxValueLength));
                    sourceKey.EnumValue(i, lpValueName.Ptr, lpcValueName.Ptr, lpReserved.Ptr, lpdwType.Ptr, lpvData.Ptr,
                                        lpcData.Ptr);

                    Win32Api.RegValueType valueType = (Win32Api.RegValueType)Marshal.ReadInt32(lpdwType.Ptr);

                    int currentValueLength = Marshal.ReadInt32(lpcData.Ptr);
                    int currentValueNameLength = Marshal.ReadInt32(lpcValueName.Ptr);

                    string currentValueName = Marshal.PtrToStringUni(lpValueName.Ptr, currentValueNameLength);

                    destinationKey.SetValue(null, currentValueName, 0, valueType, lpvData.Ptr, currentValueLength);
                }
            }
        }

        // TODO: Copy security for keys
        internal static void CopyTree(this VirtualRegistry virtualRegistry, IntPtr hKeySrcParent, string lpSubKey, IntPtr hKeyDest)
        {
            IntPtr hKeySrc;
            virtualRegistry.OpenKey(hKeySrcParent, lpSubKey, 0, Win32Api.KeySecurity.MAXIMUM_ALLOWED, out hKeySrc);
            try
            {
                VirtualKey sourceKey = virtualRegistry.GetKey(hKeySrc);
                VirtualKey destinationKey = virtualRegistry.GetKey(hKeyDest);

                KeyInfo sourceKeyInfo = sourceKey.QueryInfo();

                // First copy values on this level 
                virtualRegistry.CopyValues(sourceKey, sourceKeyInfo, destinationKey);

                KeyNameAndClass[] subKeysNamesAndClasses = sourceKey.GetSubKeysInformation(sourceKeyInfo);

                // Copy keys first
                for (int i = 0; i < sourceKeyInfo.SubKeysNumber; ++i)
                {
                    string currentName = subKeysNamesAndClasses[i].Name;
                    string currentClass = subKeysNamesAndClasses[i].Class;

                    IntPtr hCurrentDestinationSubKey;
                    virtualRegistry.CreateKey(hKeyDest, currentName, 0, currentClass, 0,
                        Win32Api.KeySecurity.MAXIMUM_ALLOWED, IntPtr.Zero,
                        out hCurrentDestinationSubKey, IntPtr.Zero);
                    try
                    {
                        // Recursively copy subtree
                        virtualRegistry.CopyTree(hKeySrc, currentName, hCurrentDestinationSubKey);
                    }
                    finally
                    {
                        virtualRegistry.CloseKey(hCurrentDestinationSubKey);
                    }
                }
            }
            finally
            {
                virtualRegistry.CloseKey(hKeySrc);
            }
        }

        internal static void DeleteTree(this VirtualRegistry virtualRegistry, IntPtr hParentKey, string lpSubKey)
        {
            VirtualKey parentKey = virtualRegistry.GetKey(hParentKey);

            IntPtr hKey;
            virtualRegistry.OpenKey(hParentKey, lpSubKey, 0,
                Win32Api.KeySecurity.MAXIMUM_ALLOWED, out hKey);
            try
            {

                VirtualKey key = virtualRegistry.GetKey(hKey);

                KeyInfo keyInfo = key.QueryInfo();
                var subKeyNamesAndClasses = key.GetSubKeysInformation(keyInfo);

                for (uint i = 0; i < keyInfo.SubKeysNumber; ++i)
                {
                    string currentName = subKeyNamesAndClasses[i].Name;
                    virtualRegistry.DeleteTree(hKey, currentName);
                }
            }
            finally
            {
                virtualRegistry.CloseKey(hKey);
            }

            parentKey.Delete(lpSubKey, Win32Api.RegWow64Options.None, 0);
        }
    }
}
