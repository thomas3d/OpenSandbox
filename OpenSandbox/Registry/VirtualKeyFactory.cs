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

namespace OpenSandbox.Registry
{
    internal interface IKeyImplOpenFactory
    {
        bool TryOpen(KeyIdentity identity, KeySecurity samDesired, out IKeyImpl openedImpl);
    }

    delegate void Callback();

    // TODO: think if there is a simpler way to override "Close" w/o delegating
    // tons of methods with tons of params...
    internal class KeyImplDecoratorHookingClose : IKeyImpl
    {
        private IKeyImpl decorated_;
        private Callback callback_;

        internal KeyImplDecoratorHookingClose(IKeyImpl decorated, Callback callback)
        {
            decorated_ = decorated;
            callback_ = callback;
        }

        public void Close()
        {
            decorated_.Close();
            callback_();
        }

        public KeyDisposition GetDisposition()
        {
            return decorated_.GetDisposition();
        }

        public KeySecurity GetAccessMode()
        {
            return decorated_.GetAccessMode();
        }

        public bool TryApply(IKeyImplHandler handler)
        {
            return decorated_.TryApply(handler);
        }

        public bool TryGetValue(string lpValue, Win32Api.RegRestrictionFlags dwFlags, IntPtr pdwType, IntPtr pvData, IntPtr pcbData)
        {
            return decorated_.TryGetValue(lpValue, dwFlags, pdwType, pvData, pcbData);
        }

        public bool TryQueryValue(string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, IntPtr lpcbData)
        {
            return decorated_.TryQueryValue(lpValueName, lpReserved, lpType, lpData, lpcbData);
        }

        public void SetValue(string lpValueName, Win32Api.RegValueType dwType, IntPtr lpData, int cbData)
        {
            decorated_.SetValue(lpValueName, dwType, lpData, cbData);
        }

        public void Delete()
        {
            decorated_.Delete();
        }

        public void DeleteValue(string lpValueName)
        {
            decorated_.DeleteValue(lpValueName);
        }

        public void EnumKey(uint dwIndex, IntPtr lpName, IntPtr lpcchName, IntPtr lpReserved, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpftLastWriteTime)
        {
            decorated_.EnumKey(dwIndex, lpName, lpcchName, lpReserved, lpClass,
                lpcchClass, lpftLastWriteTime);
        }

        public void EnumValue(uint dwIndex, IntPtr lpValueName, IntPtr lpcchValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, IntPtr lpcbData)
        {
            decorated_.EnumValue(dwIndex, lpValueName, lpcchValueName, lpReserved,
                lpType, lpData, lpcbData);
        }

        public void QueryInfo(IntPtr lpClass, IntPtr lpcbClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, IntPtr lpftLastWriteTime)
        {
            decorated_.QueryInfo(lpClass, lpcbClass, lpReserved, lpcSubKeys,
                lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen,
                lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
        }
    }

    internal class NotPredefinedBaseKeyManager
    {
        internal void BaseKeyCopied(IntPtr baseKey)
        {
            if (KeyIdentity.IsPredefined(baseKey)) return;
            Int64 key = baseKey.ToInt64();
            lock (this)
            {
                if (!baseKeyRefCount_.ContainsKey(key)) baseKeyRefCount_[key] = 0;
                baseKeyRefCount_[key]++;
            }
        }

        internal void BaseKeyClosed(IntPtr baseKey)
        {
            if (KeyIdentity.IsPredefined(baseKey)) return;
            Int64 key = baseKey.ToInt64();
            lock (this)
            {
                baseKeyRefCount_[key]--;
                if (baseKeyRefCount_[key] == 0)
                {
                    baseKeyRefCount_.Remove(key);
                    Win32Exception.CheckResult(Win32Api.RegCloseKey(baseKey));
                }
            }
        }

        private Dictionary<Int64, int> baseKeyRefCount_ = new Dictionary<long,int>();
    }

    internal class VirtualKeyFactory : DisposableBase
    {
        private WindowsKeyFactory windowsKeyFactory_ = new WindowsKeyFactory();
        private OffRegHive baseHive_;
        private OffRegHive diffHive_;
        private NotPredefinedBaseKeyManager baseKeyManager_ =
            new NotPredefinedBaseKeyManager();
        private DataAlterer alterer_;

        internal OffRegHive ChangeableHive { get { return diffHive_; } }

        internal VirtualKeyFactory(string baseHivePath,
            string diffHivePath, DataAlterer alterer)
        {
            // It is allowed for tests that base hive is not used
            if (baseHivePath != null)
                baseHive_ = new OffRegHive(KeyDisposition.BASE_HIVE, baseHivePath);
            diffHive_ = new OffRegHive(KeyDisposition.DIFF_HIVE, diffHivePath, readOnly: false);
            alterer_ = alterer;
        }

        protected override void DisposeManaged()
        {
            if (baseHive_ != null)
            {
                baseHive_.Dispose();
                baseHive_ = null;
            }
            if (diffHive_ != null)
            {
                diffHive_.Dispose();
                diffHive_ = null;
            }
        }

        internal IKeyImpl Open(KeyDisposition disposition, KeyIdentity identity,
            KeySecurity samDesired)
        {
            IKeyImpl result;
            if (!TryOpen(null, disposition, identity, samDesired, out result))
                throw new FileNotFoundException();
            return result;
        }

        // returns false if the key does not exist in the given disposition,
        // on other errors throws exception.
        private bool TryOpen(KeyIdentity existingBase, KeyDisposition disposition, KeyIdentity identity,
            KeySecurity samDesired, out IKeyImpl openedImpl)
        {
            if (!TryOpenImpl(existingBase, disposition, identity, samDesired, out openedImpl))
                return false;
            baseKeyManager_.BaseKeyCopied(identity.BaseKey);
            openedImpl = new KeyImplDecoratorHookingClose(openedImpl,
                () => baseKeyManager_.BaseKeyClosed(identity.BaseKey));
            return true;
        }

        // existingBase is passed for performance optimization
        // TODO: encapsulate existingBase in a class and extract methods
        // with it a first argument there
        private bool TryOpenImpl(KeyIdentity existingBase, KeyDisposition disposition,
            KeyIdentity identity, KeySecurity samDesired, out IKeyImpl openedImpl)
        {
            openedImpl = null;
            if (disposition != KeyDisposition.DIFF_HIVE)
            {
                if (diffHive_.IsMarkedAsDeleted(existingBase, identity))
                {
                    return false;
                }
            }
            IKeyImplOpenFactory factory = null;
            switch (disposition)
            {
                case KeyDisposition.WINDOWS_REG:
                    factory = windowsKeyFactory_;
                    break;
                case KeyDisposition.BASE_HIVE:
                    factory = baseHive_;
                    break;
                case KeyDisposition.DIFF_HIVE:
                    factory = diffHive_;
                    break;
            }
            if (factory == null)
            {
                // In case if specified hive is not used (currently used
                // only for null baseHive_)
                return false;
            }
            return factory.TryOpen(identity, samDesired, out openedImpl);
        }

        internal IKeyImpl Create(KeyIdentity identity, string lpClass,
            Win32Api.RegOption dwOptions, IntPtr lpSecurityDescriptor,
            IntPtr lpdwDisposition)
        {
            return diffHive_.Create(identity, lpClass, dwOptions, lpSecurityDescriptor,
                lpdwDisposition);
        }

        internal void Save()
        {
            diffHive_.Save();
        }

        private bool KeyExists(KeyDisposition disposition, KeyIdentity identity)
        {
            try
            {
                // TODO: perhaps use MAX_ALLOWED access here instead of READ
                IKeyImpl windowsKey;
                if (!TryOpen(null, disposition, identity,
                    new KeySecurity(Win32Api.KeySecurity.STANDARD_RIGHTS_READ),
                    out windowsKey))
                {
                    // Key does not exist
                    return false;
                }
                windowsKey.Close();
                return true;
            }
            catch (Win32Exception)
            {
                // Other error
                return false;
            }
        }

        private bool KeyExistsInROHives(KeyIdentity identity)
        {
            return KeyExists(KeyDisposition.WINDOWS_REG, identity) ||
                KeyExists(KeyDisposition.BASE_HIVE, identity);
        }

        private bool TryOpenOrCreateDiffKey(KeyIdentity existingBase, KeyIdentity identity,
            KeySecurity samDesired, out IKeyImpl openedImpl)
        {
            if (TryOpen(existingBase, KeyDisposition.DIFF_HIVE, identity, samDesired, out openedImpl))
                return true;
            // If some modification operation is requested and offreg key
            // does not exist, but it is in one of readonly hives - creating it
            if (samDesired.IsOnlyForRead() ||
                !KeyExistsInROHives(identity))
            {
                return false;
            }
            try
            {
                openedImpl = Create(identity,
                    null, (int)Win32Api.RegOption.REG_OPTION_NON_VOLATILE, IntPtr.Zero,
                    IntPtr.Zero);
                return true;
            }
            catch (FileNotFoundException)
            {
                return false;
            }
        }

        private static bool CheckSystemKeyAccess(KeyDisposition disposition,
            KeyIdentity identity, KeySecurity samDesired)
        {
            // This way we redirect system registry locations into windows registry
            // and make it fail for write operations
            if (disposition != KeyDisposition.WINDOWS_REG &&
                identity.IsSystemKey())
            {
                if (samDesired.IsOnlyForRead())
                {
                    // So that it retries to read from system registry
                    return false;
                }
                // So that user gets appropriate error code
                throw new AccessDeniedException();
            }
            return true;
        }

        private static void CheckReadOnlyHivesAccess(KeyDisposition disposition,
            KeySecurity samDesired)
        {
            if (disposition != KeyDisposition.DIFF_HIVE)
            {
                Debug.Assert(samDesired.IsOnlyForRead());
                if (!samDesired.IsOnlyForRead())
                {
                    throw new AccessDeniedException();
                }
            }
        }
/*
        public KeyImplHolder OpenHolder(KeyDisposition disposition,
            KeyIdentity identity, KeySecurity samDesired)
        {
            KeyImplHolder result;
            if (!TryOpenHolder(disposition, identity, samDesired, out result))
                throw new FileNotFoundException();
            return result;
        }
*/
        public bool TryOpenHolder(KeyIdentity existingBase, KeyDisposition disposition,
            KeyIdentity identity, KeySecurity samDesired, out KeyImplHolder openedHolder)
        {
            openedHolder = null;
            // ATTENTION: it is not clear if this function works fine if
            // lpSubKey == null is given for a predefined key, may be it will fail
            // trying to close the predefined key or something. Check later.

            // This way we redirect system registry locations into windows registry
            // and make it fail for write operations
            if (!CheckSystemKeyAccess(disposition, identity, samDesired))
                return false;

            CheckReadOnlyHivesAccess(disposition, samDesired);

            IKeyImpl registryKey;
            if (disposition != KeyDisposition.DIFF_HIVE)
            {
                if (!TryOpen(existingBase, disposition, identity, samDesired, out registryKey))
                    return false;
            }
            else
            {
                if (!TryOpenOrCreateDiffKey(existingBase, identity, samDesired, out registryKey))
                    return false;
            }
            openedHolder = new KeyImplHolder(registryKey);
            return true;
        }

        private bool TryOpenKey(KeyIdentity existingBase, KeyDisposition disposition,
            KeyIdentity identity, KeySecurity samDesired, out VirtualKey key)
        {
            KeyImplHolder holder;
            key = null;
            if (!TryOpenHolder(existingBase, disposition, identity, samDesired, out holder))
                return false;
            key = new VirtualKey(this, identity, holder.ReleaseKeyImpl(), alterer_);
            return true;
        }

        // Opens virtual key not for regular operation, but just
        // when RegOpen*/RegCreate* is called, so access checking is not so strict
        // as for operation
        // TODO: don't check security access mode on open,
        // make just a reg function call check it
        internal VirtualKey OpenKeyPreliminarily(KeyIdentity existingBase, KeyIdentity identity, KeySecurity samDesired)
        {
            foreach (KeyDisposition disposition in VirtualKey.HIVES_ORDER)
            {
                try
                {
                    VirtualKey key;
                    if (TryOpenKey(existingBase, disposition, identity, samDesired, out key))
                        return key;
                    // Key not found
                    if (!samDesired.IsOnlyForRead())
                    {
                        // Key not present in reghive and write access requested
                        // we can't give it in hives other than DIFF_HIVE
                        throw new FileNotFoundException();
                    }
                }
                catch (AccessDeniedException)
                {
                    if (!identity.IsSystemKey() || disposition == KeyDisposition.WINDOWS_REG)
                    {
                        // Access denied in reghive (may happen if key is system key)
                        // but if not a system key
                        throw;
                    }
                }
                if (identity.IsSystemKey() && !samDesired.IsOnlyForRead())
                {
                    // Relaxing access (some apps request write access and do not use it
                    // we want to make them work
                    samDesired.RelaxToReadAccess();
                }
            }
            throw new FileNotFoundException();
        }

        internal VirtualKey CreateKey(KeyIdentity identity, string lpClass,
            Win32Api.RegOption dwOptions, IntPtr lpSecurityAttributes)
        {
            // Security attributes and security descriptor are not the same
            IntPtr securityDescriptor = IntPtr.Zero;
            if (lpSecurityAttributes != IntPtr.Zero)
            {
                Win32Api.SECURITY_ATTRIBUTES securityAttributes =
                    (Win32Api.SECURITY_ATTRIBUTES)Marshal.PtrToStructure(
                        lpSecurityAttributes, typeof(Win32Api.SECURITY_ATTRIBUTES));
                if (securityAttributes.nLength >=
                    Marshal.SizeOf(typeof(UInt32)) + Marshal.SizeOf(typeof(IntPtr)))
                {
                    securityDescriptor = securityAttributes.lpSecurityDescriptor;
                }
            }
            IKeyImpl registryKey = Create(identity, lpClass, dwOptions,
                securityDescriptor, IntPtr.Zero);
            return new VirtualKey(this, identity, registryKey, alterer_);
        }
    }
}
