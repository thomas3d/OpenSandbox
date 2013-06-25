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
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSandbox.Registry
{

    internal class OffRegApi
    {
        #region Common Declarations

        /// <summary>
        /// Advapi32 dll name.
        /// </summary>
        internal const string OffRegDllName = "offreg.dll";


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

        #endregion

        #region Offline Registry Functions API

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORCreateHive(out IntPtr rootKeyHandle);

        // This function allows to open hive as many times as possible,
        // not locking it in any way
        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 OROpenHive(string path, out IntPtr rootKeyHandle);

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORCloseHive(IntPtr rootKeyHandle);

        #region ORSaveHive function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORSaveHive(
            IntPtr rootKeyHandle,
            string path,
            uint dwOsMajorVersion,
            uint dwOsMinorVersion);

        #endregion

        #region ORCloseKey function

        [DllImport(OffRegDllName)]
        internal static extern Int32 ORCloseKey(IntPtr hKey);

        #endregion

        #region ORCreateKey function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORCreateKey(
            IntPtr hKey, 
            String lpSubKey, 
            String lpClass,
            Win32Api.RegOption dwOptions,
            /*ref SECURITY_DESCRIPTOR*/ IntPtr lpSecurityDescriptor,
            /*ref IntPtr*/ out IntPtr phkResult,
            /*ref RegKeyDisposition*/ IntPtr lpdwDisposition);

        #endregion

        #region ORDeleteKey function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORDeleteKey(
            IntPtr hKey,
            String lpSubKey);

        #endregion

        #region ORDeleteValue function

        internal const String RegDeleteValueFuncName = "RegDeleteValueW";

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORDeleteValue(
            IntPtr hKey,
            String lpValueName);

        #endregion

        #region OREnumKey function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 OREnumKey(
            IntPtr hKey,
            UInt32 dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref FILETIME*/ IntPtr lpftLastWriteTime);

        #endregion

        #region OREnumValue function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 OREnumValue(
            IntPtr hKey,
            UInt32 dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            /*ref RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData);

        #endregion

        #region ORGetKeySecurity function

        [DllImport(OffRegDllName)]
        internal static extern Int32 ORGetKeySecurity(
            IntPtr hKey,
            Win32Api.SECURITY_INFORMATION SecurityInformation,
            IntPtr pSecurityDescriptor,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor);

        #endregion

        #region ORGetValue function

        internal const String RegGetValueFuncName = "RegGetValueW";

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORGetValue(
            IntPtr hKey,
            String lpSubKey,
            String lpValue,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData);

        #endregion

        #region OROpenKey function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 OROpenKey(
            IntPtr hKey,
            String lpSubKey,
            /*ref IntPtr*/ out IntPtr phkResult);

        #endregion

        #region ORQueryInfoKey function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORQueryInfoKey(
            IntPtr hKey,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref UInt32*/ IntPtr lpcSubKeys,
            /*ref UInt32*/ IntPtr lpcbMaxSubKeyLen,
            /*ref UInt32*/ IntPtr lpcbMaxClassLen,
            /*ref UInt32*/ IntPtr lpcValues,
            /*ref UInt32*/ IntPtr lpcbMaxValueNameLen,
            /*ref UInt32*/ IntPtr lpcbMaxValueLen,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor,
            /*ref FILETIME*/ IntPtr lpftLastWriteTime);

        #endregion

        #region ORSetValue function

        [DllImport(OffRegDllName, CharSet = CharSet.Unicode)]
        internal static extern Int32 ORSetValue(
            IntPtr hKey,
            String lpValueName,
            Win32Api.RegValueType dwType,
            IntPtr lpData,
            int cbData);

        #endregion

        #region ORSetKeySecurity function

        [DllImport(OffRegDllName)]
        internal static extern Int32 ORSetKeySecurity(
            IntPtr hKey,
            Win32Api.SECURITY_INFORMATION SecurityInformation,
            /*ref IntPtr*/ IntPtr pSecurityDescriptor);

        #endregion

        #endregion
    }
}
