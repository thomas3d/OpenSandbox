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
    // Virtual key does not take responsibility for closing itself.
    // It is totally user's responsibility to close it.
    // However it takes responsibility for cleaning up allocated resources at
    // determined moment: when Dispose is called.
    internal class VirtualKey : DisposableBase, IKey
    {
        private VirtualKeyFactory opener_;
        private KeyIdentity identity_;
        // Base keyImpl is stored to be able to differentiate it
        // from keyImpls in cache and close it if Close is called
        // and avoid closing if Dispose is called
        private IKeyImpl baseImpl_;
        private DataAlterer alterer_;
        // TODO: think if cache might be global, not just for single VirtualKey
        private KeyImplCache cachedKeyImpls_ = new KeyImplCache();

        internal KeyIdentity Identity { get { return identity_; } }

        internal static KeyDisposition[] HIVES_ORDER = new KeyDisposition[] { 
            KeyDisposition.DIFF_HIVE, KeyDisposition.BASE_HIVE, KeyDisposition.WINDOWS_REG};
        internal static KeyDisposition[] HIVES_REVERSE_ORDER;

        static VirtualKey()
        {
            HIVES_REVERSE_ORDER = new KeyDisposition[HIVES_ORDER.Length];
            for (int i = 0; i < HIVES_ORDER.Length; ++i)
            {
                HIVES_REVERSE_ORDER[HIVES_ORDER.Length - i - 1] = HIVES_ORDER[i];
            }
        }

        internal VirtualKey(VirtualKeyFactory opener, KeyIdentity identity,
            IKeyImpl baseKeyImpl, DataAlterer alterer)
        {
            opener_ = opener;
            identity_ = identity;
            baseImpl_ = baseKeyImpl;
            alterer_ = alterer;
            ReinitializeCache();
        }

        public void Close()
        {
            // TODO: move closing of cache into Dispose of VirtualKey otherwise
            // if user forgets to call Close, the cached keys remain open
            // which is incorrect by definition and may lead to calls to
            // ORCloseKey from finalizers
            baseImpl_.Close();
            Dispose();
        }

        protected override void DisposeManaged()
        {
            // TODO: The original keyImpl associated with the key
            // and added to the cache as the first one should not be closed here
            // (if user forgets to call RegCloseKey, key should not be closed
            // on sandbox shutdown)
            cachedKeyImpls_.Dispose();
        }

        private bool TryGetSubKey(KeyDisposition disposition, string lpSubKey,
            KeySecurity samDesired, Win32Api.RegWow64Options wowOptions, out KeyImplHolder subKeyHolder)
        {
            KeyIdentity subKeyIdentity = new KeyIdentity(identity_, wowOptions, lpSubKey);
            IKeyImpl keyImpl = cachedKeyImpls_.TryGet(subKeyIdentity, disposition, samDesired);
            if (keyImpl != null)
            {
                subKeyHolder = new NotOwningKeyImplHolder(keyImpl);
                return true;
            }
            KeyImplHolder newOne;
            if (!opener_.TryOpenHolder(identity_, disposition, subKeyIdentity, samDesired, out newOne))
            {
                subKeyHolder = null;
                return false;
            }
            subKeyHolder = cachedKeyImpls_.Add(subKeyIdentity, disposition, newOne);
            return true;
        }

        // returns false on FileNotFound error, otherwise - throws exception
        internal delegate bool KeyImplOperation(IKeyImpl keyImpl);

        // returns false in case of FileNotFound error, otherwise throws exception
        internal bool TryApplyOperation(KeyDisposition disposition, string subKeyName,
            KeySecurity samDesired, KeyImplOperation operation,
            Win32Api.RegWow64Options wowOptions = Win32Api.RegWow64Options.None)
        {
            // None is passed from Get/Set/Enum operations which does not allow user to pass wow options
            // in such case we take it from the current identity
            if (wowOptions == Win32Api.RegWow64Options.None) wowOptions = identity_.GetWow64Mode();
            KeyImplHolder subKey;
            if (!TryGetSubKey(disposition, subKeyName, samDesired, wowOptions, out subKey))
                return false;
            using (subKey)
            {
                // TODO: almost always the operation needs subKey name, at least for logging
                // so it is constructed second time there.
                // Better to pass it from here.
                try
                {
                    if (!operation(subKey.GetKeyImpl()))
                        return false;
                }
                catch (FileNotFoundException)
                {
                    // TODO: make all operations return false in case of FileNotFoundException
                    // so that this catch can be removed.
                    return false;
                }
            }
            return true;
        }

        internal void ApplyReadOperation(string subKeyName, KeySecurity samDesired,
            KeyImplOperation operation)
        {
            Debug.Assert(samDesired.IsOnlyForRead());
            if (!samDesired.IsOnlyForRead())
            {
                throw new AccessDeniedException();
            }

            foreach (KeyDisposition disposition in HIVES_ORDER)
            {
                if (TryApplyOperation(disposition, subKeyName, samDesired, operation))
                    return;
            }
            throw new FileNotFoundException();
        }

        internal void ApplyNotOnlyReadOperation(string subKeyName,
            KeySecurity samDesired, KeyImplOperation operation,
            Win32Api.RegWow64Options wowOptions = Win32Api.RegWow64Options.None)
        {
            if (!TryApplyOperation(KeyDisposition.DIFF_HIVE, subKeyName, samDesired, operation, wowOptions))
                throw new FileNotFoundException();
        }

        private bool TryAlterData(string subKey, string value, IKeyImpl keyImpl,
            IntPtr pdwType, Data dst, DataTransformer.Operation operation)
        {
            return alterer_.TryAlterData(new KeyIdentity(identity_, Win32Api.RegWow64Options.None, subKey),
                value, keyImpl, pdwType, dst, operation);
        }

        // TODO: group parameters of every operation function and put them into separate classes
        // This overload is to implement IKey
        public void GetValue(
            string lpValue,
            Win32Api.RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData)
        {
            GetValue(null, lpValue, dwFlags, pdwType, pvData, pcbData);
        }

        internal void GetValue(
            string lpSubKey,
            string lpValue,
            Win32Api.RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData)
        {
            ApplyReadOperation(lpSubKey, new KeySecurity(Win32Api.KeySecurity.KEY_QUERY_VALUE),
                keyImpl => 
                    TryAlterData(lpSubKey, lpValue, keyImpl, pdwType,
                        new Data(pvData, pcbData, Data.CountIn.Bytes),
                        (newpdwType, dst) =>
                            Win32Exception.CatchError(
                                () => keyImpl.TryGetValue(lpValue, dwFlags, newpdwType,
                                    dst.Ptr, dst.PCount))));
        }

        // This overload is to implement IKey
        public void QueryValue(
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData)
        {
            QueryValue(null, lpValueName, lpReserved, lpType, lpData, lpcbData);
        }

        public void QueryValue(
            string lpSubKey,
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData)
        {
            // This function is implemented explicitely and separately from
            // GetValue because RegQueryValue and RegGetValue behavior in regard
            // to strings and null characters differ.
            ApplyReadOperation(lpSubKey, new KeySecurity(Win32Api.KeySecurity.KEY_QUERY_VALUE),
                keyImpl => 
                    TryAlterData(lpSubKey, lpValueName, keyImpl, lpType,
                        new Data(lpData, lpcbData, Data.CountIn.Bytes),
                        (newpdwType, dst) =>
                            Win32Exception.CatchError(
                                () => keyImpl.TryQueryValue(lpValueName, lpReserved, newpdwType,
                                    dst.Ptr, dst.PCount))));
        }

        public void SetValue(
            string lpValueName,
            Win32Api.RegValueType dwType,
            IntPtr lpData,
            int cbData)
        {
            SetValue(null, lpValueName, 0, dwType, lpData, cbData);
        }

        internal void SetValue(
            string lpSubKey,
            string lpValueName,
            int Reserved,
            Win32Api.RegValueType dwType,
            IntPtr lpData,
            int cbData)
        {
            ApplyNotOnlyReadOperation(lpSubKey, new KeySecurity(Win32Api.KeySecurity.KEY_SET_VALUE),
                keyImpl =>
                {
                    keyImpl.SetValue(lpValueName, dwType, lpData, cbData);
                    return true;
                });
        }

        public void Delete()
        {
            Delete(null, Win32Api.RegWow64Options.None, 0);
        }

        private void ReinitializeCache()
        {
            cachedKeyImpls_.Clear();
            // Ignoring return value because cache is empty ad the impl is added for sure
            cachedKeyImpls_.Add(identity_, baseImpl_.GetDisposition(),
                new NotOwningKeyImplHolder(baseImpl_));
        }

        internal void Delete(
            string lpSubKey,
            Win32Api.RegWow64Options samDesired,
            int Reserved)
        {
            // We try to delete offreg hive key
            // and we do nothing with the windows key
            // Thus postcondition of this operation is not met, but this is
            // our application logic and concious decision
            ApplyNotOnlyReadOperation(lpSubKey, new KeySecurity(Win32Api.KeySecurity.DELETE),
                keyImpl =>
                {
                    keyImpl.Delete();
                    // Cache is cleared here because in cache there may be keyImpls
                    // pointing to the deleted key, or its subkeys, which prevent
                    // actual deleting of the key until the VirtualKey is closed otherwise.
                    // And the marking key as deleted won't work if cache is not cleared for the same reason.
                    ReinitializeCache();
                    return true;
                },
                samDesired);
            // If there is a key in a higher order hive, marking it as deleted
            try
            {
                ApplyReadOperation(lpSubKey, new KeySecurity(Win32Api.KeySecurity.KEY_READ),
                    keyImpl =>
                    {
                        opener_.ChangeableHive.MarkKeyAsDeleted(
                        new KeyIdentity(identity_, samDesired, lpSubKey));
                        return true;
                    });
            }
            catch (Win32Exception)
            {
                // Suppressing all errors like file not found (means no need to mark the
                // key as deleted), or access denied (means deletion can't be performed)
            }
        }

        public void DeleteValue(string lpValueName)
        {
            DeleteValue(null, lpValueName);
        }

        internal void DeleteValue(
            string lpSubKey,
            string lpValueName)
        {
            // TODO: mark values deleted from windows registry so that they are not returned
            // from GetValue/EnumValue
            ApplyNotOnlyReadOperation(lpSubKey, new KeySecurity(Win32Api.KeySecurity.KEY_SET_VALUE),
                keyImpl =>
                {
                    keyImpl.DeleteValue(lpValueName);
                    return true;
                });
        }

        // TODO: generalize the order in which enumeration operations are performed
        // and create smth like ApplyEnumOperation
        public void EnumKey(
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref Win32Api.FILETIME*/ IntPtr lpftLastWriteTime)
        {
            // TODO: this function does not take into accout the intersection
            // of subkey names between windows regisry key and offreg key, this is 
            // to be done in a next version

            // It does not matter in which hive the current key is
            // we need to open and enumerate them all
            foreach (KeyDisposition disposition in HIVES_REVERSE_ORDER)
            {
                bool indexHandled = false;
                // Requesting access rights for both RegEnumKey and RegQueryInfoKey operations
                TryApplyOperation(disposition, null,
                    new KeySecurity(Win32Api.KeySecurity.KEY_ENUMERATE_SUB_KEYS |
                        Win32Api.KeySecurity.KEY_QUERY_VALUE), keyImpl =>
                    {
                        try
                        {
                            keyImpl.EnumKey(dwIndex, lpName, lpcchName, lpReserved, lpClass,
                                lpcchClass, lpftLastWriteTime);

                            indexHandled = true;
                        }
                        catch (Win32Exception e)
                        {
                            if (e.ErrorCode != (int)Win32Api.Error.ERROR_NO_MORE_ITEMS)
                            {
                                throw;
                            }
                            uint cSubKeys = keyImpl.QueryInfo().SubKeysNumber;
                            // Assumming here that dwIndex >= cSubKeys, but this might
                            // be false if key has been changed between calls to EnumKey and QueryInfo
                            dwIndex -= cSubKeys;
                        }
                        return true;
                    });
                if (indexHandled) return;
            }
            throw Win32Exception.Create((int)Win32Api.Error.ERROR_NO_MORE_ITEMS);
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
            // TODO: this function does not take into account the intersection
            // of value names between windows regisry key and offreg key, this is 
            // to be done in the next version

            // It does not matter if the current key is open in windows registry or in offreg
            // we need to open and enumerate both them
            int cchValueName = 0;
            if (lpcchValueName != IntPtr.Zero) cchValueName = Marshal.ReadInt32(lpcchValueName);
            KeyImplOperation enumValue = keyImpl =>
                TryAlterData(null, null, keyImpl, lpType,
                    new Data(lpData, lpcbData, Data.CountIn.Bytes),
                    (newpdwType, dst) =>
                        Win32Exception.CatchError(
                            () =>
                            {
                                // EnumValue takes buffer size WITH null character
                                // but returns WITHOUT, so we need to reset input
                                // param to allow multiple calls to the operation
                                if (lpcchValueName != IntPtr.Zero)
                                {
                                    Marshal.WriteInt32(lpcchValueName, cchValueName);
                                }
                                keyImpl.EnumValue(dwIndex, lpValueName,
                                    lpcchValueName, lpReserved, newpdwType,
                                    dst.Ptr, dst.PCount);
                            }));

            foreach (KeyDisposition disposition in HIVES_REVERSE_ORDER)
            {
                bool indexHandled = false;
                TryApplyOperation(disposition, null,
                    new KeySecurity(Win32Api.KeySecurity.KEY_QUERY_VALUE), keyImpl =>
                    {
                        uint cValues = keyImpl.QueryInfo().ValuesNumber;
                        if (dwIndex < cValues)
                        {
                            enumValue(keyImpl);
                            indexHandled = true;
                        }
                        else
                        {
                            dwIndex -= cValues;
                        }
                        return true;
                    });
                if (indexHandled) return;
            }
            throw Win32Exception.Create((int)Win32Api.Error.ERROR_NO_MORE_ITEMS);
        }

        // TODO: query info does not take data altering into account,
        // data may be replaced by some larger data and this may lead to
        // buffer overflow in client's code
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
            // TODO: this function does not take into accout the intersection
            // of subkey names between windows regisry key and offreg key, and
            // the same thing about value names, this is 
            // to be done in the next version

            // It does not matter if the current key is open in windows registry or in offreg
            // we need to open and both of them

            // if the class or security descriptor is defined for both of keys and are 
            // different, then the values of windows registry keys just take priority.

            // TODO: during implementation of RegSetSecurity* probably the logic should be
            // changed to take security descriptor from OffReg key if it is there
            bool callSucceeded = false;
            KeyInfo result = new KeyInfo();

            foreach (KeyDisposition disposition in HIVES_REVERSE_ORDER)
            {
                KeyInfo current = new KeyInfo();
                if (!TryApplyOperation(disposition, null,
                    new KeySecurity(Win32Api.KeySecurity.KEY_QUERY_VALUE),
                    keyImpl =>
                    {
                        current = keyImpl.QueryInfo();
                        return true;
                    }))
                {
                    continue;
                }

                // Taking class and security descriptor from higher level (windows registry)
                // if possible, this is subject to change as soon as Reg*Security functions
                // are implemented
                if (!callSucceeded)
                {
                    result.Class = current.Class;
                    result.SecurityDescriptorLength = current.SecurityDescriptorLength;
                }

                callSucceeded = true;

                result.SubKeysNumber += current.SubKeysNumber;
                result.MaxSubKeyLength = Math.Max(result.MaxSubKeyLength,
                    current.MaxSubKeyLength);
                result.MaxClassLength = Math.Max(result.MaxClassLength,
                    current.MaxClassLength);
                result.ValuesNumber += current.ValuesNumber;
                result.MaxValueNameLength = Math.Max(result.MaxValueNameLength,
                    current.MaxValueNameLength);
                result.MaxValueLength = Math.Max(result.MaxValueLength,
                    current.MaxValueLength);
                if (DateTime.FromFileTime(result.LastWriteTime.AsLong) <
                    DateTime.FromFileTime(current.LastWriteTime.AsLong))
                {
                    result.LastWriteTime = current.LastWriteTime;
                }
            }
            // At least one of windows or OffReg key exists (because it is open
            // and passed as hKey to this function), so at least one of calls did not return
            // FILE_NOT_FOUND, thus suppressing it here

            if (lpcSubKeys != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpcSubKeys, unchecked((int)result.SubKeysNumber));
            }
            if (lpcbMaxSubKeyLen != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpcbMaxSubKeyLen, unchecked((int)result.MaxSubKeyLength));
            }
            if (lpcbMaxClassLen != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpcbMaxClassLen, unchecked((int)result.MaxClassLength));
            }
            if (lpcValues != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpcValues, unchecked((int)result.ValuesNumber));
            }
            if (lpcbMaxValueNameLen != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpcbMaxValueNameLen, unchecked((int)result.MaxValueNameLength));
            }
            if (lpcbMaxValueLen != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpcbMaxValueLen, unchecked((int)result.MaxValueLength));
            }
            if (lpftLastWriteTime != IntPtr.Zero)
            {
                Marshal.StructureToPtr(result.LastWriteTime, lpftLastWriteTime, true);
            }
            Win32Exception.CheckResult(
                new Data(lpClass, lpcClass, Data.CountIn.Chars).FillWithString(
                    new ManagedString(result.Class),
                    HookBarrier.IsLastInjectedFuncAnsi ? StringFormat.Ansi : StringFormat.Unicode,
                    Data.NullCharHandling.NotCountingOnReturn));
        }
        // TODO: extract operations not using private members
        // and large operations into separate classes.
    }
}
