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
using System.Runtime.InteropServices;
using OpenSandbox.Logging;

namespace OpenSandbox.Registry
{
    internal class VirtualRegistry : DisposableBase
    {
        private VirtualKeyFactory factory_;
        private VirtualKeyStorage keyStorage_;
        private DataAlterer alterer_ = new DataAlterer();

        // This is for tests
        internal VirtualRegistry(string baseHivePath)
            : this(baseHivePath, baseHivePath + ".local")
        { }

        internal VirtualRegistry(string baseHivePath, string diffHivePath)
        {
            factory_ = new VirtualKeyFactory(baseHivePath, diffHivePath, alterer_);
            keyStorage_ = new VirtualKeyStorage(this);
        }

        protected override void DisposeManaged()
        {
            if (factory_ != null)
            {
                // Key storage should be disposed first as disposing
                // factory closes reghives.
                keyStorage_.Dispose();
                keyStorage_ = null;
                factory_.Dispose();
                factory_ = null;
            }
        }

        internal DataAlterer DataAlterer { get { return alterer_; } }

        internal VirtualKey CreatePredefinedKey(IntPtr hKey)
        {
            KeyIdentity identity = new KeyIdentity(hKey);
            return new VirtualKey(factory_, identity, factory_.Open(
                    KeyDisposition.WINDOWS_REG, identity, new KeySecurity(Win32Api.KeySecurity.KEY_READ)),
                alterer_);
        }

        private void OpenKey(KeyIdentity existingBase, KeyIdentity identity, KeySecurity samDesired,
            out IntPtr phkResult)
        {
            phkResult = IntPtr.Zero;
            phkResult = keyStorage_.Add(
                factory_.OpenKeyPreliminarily(existingBase, identity, samDesired));
        }

        private VirtualKey GetKeyOrPickUp(IntPtr hKey)
        {
            if (hKey == IntPtr.Zero)
            {
                return null;
            }
            VirtualKey key = keyStorage_.Get(hKey);
            if (key != null)
            {
                return key;
            }
            // The key might be open by a native Reg* function before
            // OpenSandbox was embedded
            try
            {
                KeyIdentity identity = new KeyIdentity(hKey);
                key = new VirtualKey(factory_, identity, factory_.Open(
                        KeyDisposition.WINDOWS_REG, identity, new KeySecurity(Win32Api.KeySecurity.KEY_READ)),
                    alterer_);
                // ATTENTION: resource leak is happening here and may lead to AV:
                // returned VirtualKey has a cache of open keys which never gets closed
                // and the base keyImpl does not get closed too.
                // Closing is called in finalizers after registry is shutdown, which is UB.

                // We put the key to the storage for the case if it will be accessed
                // further and to avoid resource leaks
                keyStorage_.Add(hKey, key);
                DebugLogger.WriteLine("Picked up key 0x{0} {1}", hKey.ToString("X"), identity);
                return key;
            }
            catch (InvalidHandleException)
            {
                return null;
            }
            catch (FileNotFoundException)
            {
                return null;
            }
        }

        internal VirtualKey GetKey(IntPtr hKey)
        {
            VirtualKey key = GetKeyOrPickUp(hKey);
            if (key == null)
            {
                throw new InvalidHandleException();
            }
            return key;
        }

        internal string GetKeyPath(IntPtr hKey)
        {
            VirtualKey key = GetKeyOrPickUp(hKey);
            if (key == null)
            {
                if (hKey == IntPtr.Zero) return "<null>";
                return KeyIdentity.UknownHKeyStr(hKey);
            }
            return key.Identity.ToString();
        }

        internal string GetKeySystemPath(IntPtr hKey)
        {
            VirtualKey key = GetKeyOrPickUp(hKey);
            if (key == null)
            {
                if (hKey == IntPtr.Zero) return "<null>";
                return KeyIdentity.UknownHKeyStr(hKey);
            }
            return key.Identity.GetSystemPath();
        }

        // Saves offreg hive
        internal void Save()
        {
            factory_.Save();
        }

        internal void OpenKey(IntPtr hKey,
            string lpSubKey,
            int ulOptions,
            Win32Api.KeySecurity samDesired,
            out IntPtr phkResult)
        {
            // ulOptions are ignored as this is a reserved parameter
            phkResult = IntPtr.Zero;
            KeySecurity keySecurity;
            Win32Api.RegWow64Options wowOptions;
            KeySecurity.ExtractWow64Options(samDesired, out keySecurity, out wowOptions);
            KeyIdentity baseIdentity = GetKey(hKey).Identity;
            OpenKey(baseIdentity, new KeyIdentity(baseIdentity, wowOptions, lpSubKey),
                keySecurity, out phkResult);
        }

        private void OpenWindowsBaseKey(IntPtr windowsBaseKey,
            KeySecurity samDesired, out IntPtr phkResult)
        {
            // There are two options:
            // 1. Opening for reading -> we create and return windows key, which is
            // closed by user call to RegCloseKey
            // 2. Opening for writing -> we call RegOpenCurrentUser so that
            // if a subkey is opened for reading, it is under the right branch
            // and we open OffReg key and return it.

            try
            {
                OpenKey(null, new KeyIdentity(windowsBaseKey), samDesired,
                    out phkResult);
            }
            catch (Exception)
            {
                // If something went wrong, we keep responsibility for closing the key
                Win32Api.RegCloseKey(windowsBaseKey);
                throw;
            }
        }

        internal void OpenCurrentUser(
            KeySecurity samDesired,
            out IntPtr phkResult)
        {
            // CurrentUser identity depends on the user to which opening
            // thread is impersonated right now, so we need to do the syscall
            // exactly at the moment and then use the returned value
            IntPtr baseKey;
            Win32Exception.CheckResult(
                Win32Api.RegOpenCurrentUser(samDesired.Value, out baseKey));
            OpenWindowsBaseKey(baseKey, samDesired, out phkResult);
        }

        internal void OpenUserClassesRoot(
            IntPtr hToken,
            UInt32 dwOptions,
            KeySecurity samDesired,
            out IntPtr phkResult)
        {
            IntPtr baseKey;
            Win32Exception.CheckResult(
                Win32Api.RegOpenUserClassesRoot(hToken, dwOptions, samDesired.Value, out baseKey));
            OpenWindowsBaseKey(baseKey, samDesired, out phkResult);
        }

        internal void CloseKey(IntPtr hKey)
        {
            GetKey(hKey).Close();
            keyStorage_.Remove(hKey);
        }

        internal void CreateKey(IntPtr hKey,
            string lpSubKey,
            int Reserved,
            string lpClass,
            Win32Api.RegOption dwOptions,
            Win32Api.KeySecurity samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            IntPtr lpdwDisposition)
        {
            phkResult = IntPtr.Zero;
            // Reserved is ignored as this is a reserved parameter
           
            try
            {
                OpenKey(hKey, lpSubKey, 0, samDesired, out phkResult);
                if (lpdwDisposition != IntPtr.Zero)
                {
                    Marshal.WriteInt32(lpdwDisposition,
                        (int)Win32Api.RegKeyDisposition.REG_OPENED_EXISTING_KEY);
                }
                return;
            }
            catch (FileNotFoundException) {}
            KeySecurity keySecurity;
            Win32Api.RegWow64Options wowOptions;
            KeySecurity.ExtractWow64Options(samDesired, out keySecurity, out wowOptions);
            VirtualKey key = factory_.CreateKey(
                new KeyIdentity(GetKey(hKey).Identity, wowOptions, lpSubKey), lpClass, dwOptions,
                lpSecurityAttributes);
            if (lpdwDisposition != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpdwDisposition,
                    (int)Win32Api.RegKeyDisposition.REG_CREATED_NEW_KEY);
            }
            phkResult = keyStorage_.Add(key);
        }
    }
}
