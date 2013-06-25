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
using System.Diagnostics;

namespace OpenSandbox.Registry
{
    internal class WindowsKeyFactory : IKeyImplOpenFactory
    {
        public bool TryOpen(KeyIdentity identity, KeySecurity samDesired, out IKeyImpl openedImpl)
        {
            WindowsKey windowsKey;
            bool result = WindowsKey.TryOpen(identity, samDesired, out windowsKey);
            openedImpl = windowsKey;
            return result;
        }
    }

    internal class WindowsKey : IKeyImpl
    {
        private IntPtr handle_;
        private KeySecurity accessMode_;

        internal IntPtr Handle { get { return handle_; } }

        public static bool TryOpen(KeyIdentity identity, KeySecurity samDesired, out WindowsKey openedImpl)
        {
            if (identity.GetRegPath() == null)
            {
                // This works fine because baseKey is always one of the predefined
                // registry keys, so its handle does not need to be duplicated
                // or closed
                openedImpl = new WindowsKey(identity.BaseKey, samDesired);
                return true;
            }
            IntPtr handle;
            int result = Win32Api.RegOpenKeyEx(identity.BaseKey, identity.GetRegPath(), 0,
                samDesired.Value | (Win32Api.KeySecurity)identity.GetWow64Mode(),
                out handle);
            openedImpl = null;
            if (!Win32Exception.CheckIfFoundAndNoError(result))
                return false;
            openedImpl = new WindowsKey(handle, samDesired);
            return true;
        }

        private WindowsKey(IntPtr handle, KeySecurity samDesired)
        {
            handle_ = handle;
            accessMode_ = samDesired;
        }

        public void Close()
        {
            // Returning error if predefined key is requested for closing
            if (Enum.IsDefined(typeof(Win32Api.RegPredefinedKeys), (int)handle_))
            {
                throw new InvalidHandleException();
            }
            Win32Exception.CheckResult(
                Win32Api.RegCloseKey(handle_));
        }

        public KeyDisposition GetDisposition() { return KeyDisposition.WINDOWS_REG; }
        public KeySecurity GetAccessMode() { return accessMode_; }

        public bool TryApply(IKeyImplHandler handler)
        {
            return handler.Handle(this);
        }

        public bool TryGetValue(
            string lpValue,
            Win32Api.RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData)
        {
            return Win32Exception.CheckIfFoundAndNoError(
                Win32Api.RegGetValue(handle_, null, lpValue, dwFlags,
                    pdwType, pvData, pcbData));
        }

        public bool TryQueryValue(
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData)
        {
            return Win32Exception.CheckIfFoundAndNoError(
                Win32Api.RegQueryValueEx(handle_, lpValueName, lpReserved,
                    lpType, lpData, lpcbData));
        }

        public void SetValue(
            string lpValueName,
            Win32Api.RegValueType dwType,
            IntPtr lpData,
            int cbData)
        {
            Win32Exception.CheckResult(
                Win32Api.RegSetKeyValue(handle_, null, lpValueName, dwType, lpData, cbData));
        }

        public void Delete()
        {
            Debug.Assert(false);
            throw new AccessDeniedException();
        }

        public void DeleteValue(string lpValueName)
        {
            Debug.Assert(false);
            throw new AccessDeniedException();
        }

        public void EnumKey(
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref Win32Api.FILETIME*/ IntPtr lpftLastWriteTime)
        {
            Win32Exception.CheckResult(
                Win32Api.RegEnumKeyEx(handle_, dwIndex, lpName, lpcchName, lpReserved,
                    lpClass, lpcchClass, lpftLastWriteTime));
        }

        public void EnumValue(
            uint dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            IntPtr lpReserved,
            /*ref Win32Api.RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData)
        {
            Win32Exception.CheckResult(
                Win32Api.RegEnumValue(handle_, dwIndex, lpValueName,
                        lpcchValueName, lpReserved, lpType, lpData, lpcbData));
        }

        public void QueryInfo(
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
            IntPtr lpftLastWriteTime)
        {
            Win32Exception.CheckResult(
                Win32Api.RegQueryInfoKey(handle_, lpClass, lpcClass, lpReserved, lpcSubKeys,
                    lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen,
                    lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime));
        }
    }
}
