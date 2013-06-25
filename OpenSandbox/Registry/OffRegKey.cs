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
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;

namespace OpenSandbox.Registry
{
    internal class OffRegKey : IKeyImpl
    {
        private OffRegHive hive_;
        private OffregLib.OffregKey key_;
        private static Dictionary<Int64, List<string>> predefinedPaths_ =
            new Dictionary<Int64, List<string>>();
        private KeyIdentity identity_;

        internal KeyIdentity Identity { get { return identity_; } }

        public static bool TryOpen(OffRegHive hive, OffregLib.OffregHive hiveImpl, KeyIdentity identity, out OffRegKey openedKey)
        {
            // TODO: possibly we need to simulate security restrictions in some way so that,
            // for instance, write operations from app w/o administrative permissions
            // to HKEY_LOCAL_MACHINE hive would fail
            List<string> paths = GetOffRegPaths(identity);
            foreach (string path in paths)
            {
                OffregLib.Win32Result result;
                OffregLib.OffregKey key;
                if (hiveImpl.Root.TryOpenSubKey(path, out key, out result))
                {
                    openedKey = new OffRegKey(hive, key, identity);
                    return true;
                }
                if ((int)result != (int)Win32Api.Error.ERROR_FILE_NOT_FOUND)
                    throw Win32Exception.Create((int)result);
            }
            openedKey = null;
            return false;
        }

        internal OffRegKey(OffRegHive hive, OffregLib.OffregKey key, KeyIdentity identity)
        {
            hive_ = hive;
            key_ = key;
            identity_ = identity;
        }

        internal OffRegKey(OffRegHive hive, OffregLib.OffregHive hiveImpl, KeyIdentity identity,
            string lpClass, Win32Api.RegOption dwOptions, IntPtr lpSecurityDescriptor,
            IntPtr lpdwDisposition)
        {
            hive_ = hive;
            identity_ = identity;
            key_ = CreateKeys(hiveImpl, GetMainOffRegPath(identity), lpClass,
                dwOptions, lpSecurityDescriptor, lpdwDisposition);
        }

        // Create key and if needed all parent keys
        private OffregLib.OffregKey CreateKeys(OffregLib.OffregHive hiveImpl, string path,
            string lpClass, Win32Api.RegOption dwOptions, IntPtr lpSecurityDescriptor,
            IntPtr lpdwDisposition)
        {
            OffregLib.OffregKey result = null;
            try
            {
                OffRegHive.ConvertException(() => result = hiveImpl.Root.OpenSubKey(path));
                return result;
            }
            catch (FileNotFoundException) { }
            // We either take the first subkey of the path, or the last
            string parentPath, subkey;
            if (KeyIdentity.PartitionPath(path, out parentPath, out subkey))
            {
                OffregLib.OffregKey parentKey = CreateKeys(hiveImpl, parentPath, lpClass, dwOptions,
                    lpSecurityDescriptor, lpdwDisposition);
                OffRegHive.ConvertException(() => parentKey.Close());
            }
            // TODO: do something with lpClass, lpSecurityDescriptor, for now they are ignored
            OffRegHive.ConvertException(() =>
                result = hiveImpl.Root.CreateSubKey(
                    path, (OffregLib.RegOption)dwOptions));
            if (lpdwDisposition != IntPtr.Zero)
            {
                Marshal.WriteInt32(lpdwDisposition, (int)Win32Api.RegKeyDisposition.REG_CREATED_NEW_KEY);
            }
            // TODO: if there is an existing key in windows registry, but we create one
            // in offreg hive, which disposition do we need to return?
            return result;
        }

        public void Close()
        {
            OffRegHive.ConvertException(() => key_.Close());
            key_ = null;
        }

        public KeyDisposition GetDisposition() { return hive_.Disposition; }
        public KeySecurity GetAccessMode() { return new KeySecurity(Win32Api.KeySecurity.KEY_ALL_ACCESS); }

        public bool TryApply(IKeyImplHandler handler)
        {
            return handler.Handle(this);
        }

        static OffRegKey()
        {
            predefinedPaths_.Add((Int64)Win32Api.RegPredefinedKeys.HKEY_CLASSES_ROOT,
                new List<string> {@"user\current_classes", @"machine\software\Classes"});
            predefinedPaths_.Add((Int64)Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER,
                new List<string> {@"user\current"});
            predefinedPaths_.Add((Int64)Win32Api.RegPredefinedKeys.HKEY_LOCAL_MACHINE,
                new List<string> {@"machine"});
            predefinedPaths_.Add((Int64)Win32Api.RegPredefinedKeys.HKEY_USERS,
                new List<string> {@"user"});
        }

        internal static List<string> GetOffRegPaths(KeyIdentity identity)
        {
            if (!predefinedPaths_.ContainsKey((Int64)identity.BaseKey))
            {
                return new List<string>();
            }
            List<string> result = new List<string>();
            List<string> basePaths = predefinedPaths_[(Int64)identity.BaseKey];
            string regPath = identity.GetRegPath();
            foreach (string basePath in basePaths)
            {
                // offreg hive does not distinguish between 32bit and 64 bit branches for now
                // so we use path w/o Wow6432Node
                result.Add(KeyIdentity.CombinePaths(basePath, regPath));
            }
            return result;
        }

        internal static string GetMainOffRegPath(KeyIdentity identity)
        {
            if (!predefinedPaths_.ContainsKey((Int64)identity.BaseKey))
            {
                // Not thrown in usual cases, may be thrown very rarely if identity.BaseKey
                // points to some specific place (may be)
                throw new FileNotFoundException();
            }
            return KeyIdentity.CombinePaths(predefinedPaths_[(Int64)identity.BaseKey][0], identity.GetRegPath());
        }

        private static bool forceU2AConversion_ = false;

        internal static bool DoUni2AnsiConversion {
            get { return HookBarrier.IsLastInjectedFuncAnsi || forceU2AConversion_; }
            // for debug
            set { forceU2AConversion_ = value; }
        }

        public bool TryGetValue(
            string lpValue,
            Win32Api.RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData)
        {
            if (!DoUni2AnsiConversion)
            {
                return Win32Exception.CheckIfFoundAndNoError((int)key_.TryGetValueUnmanaged(lpValue, pdwType, pvData, pcbData));
            }
            Data dst = new Data(pvData, pcbData, Data.CountIn.Bytes);
            // Sandboxie-generated reghives might contain REG_SZ values stored in ansi format
            // we need to detect them and avoid conversion for them

            return DataTransformer.TryAlterData(pdwType, dst,
                (newpdwType, newDst) =>
                    (int)key_.TryGetValueUnmanaged(lpValue, newpdwType, newDst.Ptr, newDst.PCount),
                (result, type) => result == Win32Api.Error.ERROR_SUCCESS &&
                    DataTransformer.IsStringType(type),
                (type, pSrcData, cbSrcData) =>
                    dst.FillWithString(new BytesString(pSrcData, cbSrcData), StringFormat.Ansi,
                        Data.NullCharHandling.NotAddingIfNotPresent));
        }

        public bool TryQueryValue(
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData)
        {
            // Function alters its documented behavior by adding null characters
            // to strings which are not null-terminated
            return TryGetValue(lpValueName, Win32Api.RegRestrictionFlags.RRF_RT_ANY, lpType, lpData,
                lpcbData);
        }

        public void SetValue(
            string lpValueName,
            Win32Api.RegValueType dwType,
            IntPtr lpData,
            int cbData)
        {
            int result;
            if (!DoUni2AnsiConversion ||
                !DataTransformer.IsStringType(dwType))
            {
                result = OffRegHive.CatchException(() =>
                    key_.SetValueUnmanaged(lpValueName, (OffregLib.RegValueType)dwType, lpData, cbData));
                hive_.MarkAsModified();
                Win32Exception.CheckResult(result);
                return;
            }
            string str = Marshal.PtrToStringAnsi(lpData, cbData);
            using (HGlobalPtr pStr =
                new HGlobalPtr(Marshal.StringToHGlobalUni(str)))
            {
                result = OffRegHive.CatchException(() =>
                    key_.SetValueUnmanaged(lpValueName, (OffregLib.RegValueType)dwType,
                        pStr.Ptr, cbData * sizeof(char)));
                hive_.MarkAsModified();
                Win32Exception.CheckResult(result);
            }
        }

        public void Delete()
        {
            int result = OffRegHive.CatchException(() => key_.Delete());
            hive_.MarkAsModified();
            Win32Exception.CheckResult(result);
        }

        public void DeleteValue(string lpValueName)
        {
            int result = OffRegHive.CatchException(() => key_.DeleteValue(lpValueName));
            hive_.MarkAsModified();
            Win32Exception.CheckResult(result);
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
            using (Uni2AnsiConverter nameConverter =
                    new Uni2AnsiConverter(new Data(lpName, lpcchName, Data.CountIn.Chars),
                        DoUni2AnsiConversion),
                classConverter =
                    new Uni2AnsiConverter(new Data(lpClass, lpcchClass, Data.CountIn.Chars),
                        DoUni2AnsiConversion))
            {
                OffRegHive.ConvertException(() =>
                    key_.EnumKeyUnmanaged(dwIndex, nameConverter.UnicodeStr,
                        lpcchName, classConverter.UnicodeStr, lpcchClass,
                        lpftLastWriteTime));
                nameConverter.Convert();
                classConverter.Convert();
            }
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
            if (!DoUni2AnsiConversion)
            {
                OffRegHive.ConvertException(() =>
                    key_.EnumValueUnmanaged(dwIndex, lpValueName,
                            lpcchValueName, lpType, lpData, lpcbData));
                return;
            }
            int cchValueName = 0;
            if (lpcchValueName != IntPtr.Zero)
            {
                cchValueName = Marshal.ReadInt32(lpcchValueName);
            }
            using (Uni2AnsiConverter nameConverter =
                new Uni2AnsiConverter(new Data(lpValueName, lpcchValueName, Data.CountIn.Chars)))
            {
                try
                {
                    Data dst = new Data(lpData, lpcbData, Data.CountIn.Bytes);
                    // Sandboxie-generated reghives might contain REG_SZ values stored in ansi format
                    // we need to detect them and avoid conversion for them
                    if (!DataTransformer.TryAlterData(lpType,
                        dst, (newpdwType, newDst) =>
                        {
                            // EnumValue takes buffer size WITH null character
                            // but returns WITHOUT, so we need to reset input
                            // param to allow multiple calls to the operation
                            if (lpcchValueName != IntPtr.Zero)
                            {
                                Marshal.WriteInt32(lpcchValueName, cchValueName);
                            }
                            return OffRegHive.CatchException(() => key_.EnumValueUnmanaged(
                                dwIndex, nameConverter.UnicodeStr,
                                lpcchValueName, newpdwType, newDst.Ptr, newDst.PCount));
                        },
                        (result, type) => (result == Win32Api.Error.ERROR_SUCCESS ||
                            result == Win32Api.Error.ERROR_MORE_DATA) &&
                            DataTransformer.IsStringType(type),
                        (type, pSrcData, cbSrcData) =>
                            dst.FillWithString(new BytesString(pSrcData, cbSrcData), StringFormat.Ansi,
                                Data.NullCharHandling.NotAddingIfNotPresent)))
                    {
                        throw new FileNotFoundException();
                    }
                    nameConverter.Convert();
                }
                catch (Win32Exception ex)
                {
                    if (ex.ErrorCode == (int)Win32Api.Error.ERROR_MORE_DATA)
                    {
                        // Assumming that in case of ERROR_MORE_DATA lpcchValueName is
                        // filled with correct value
                        nameConverter.Convert();
                    }
                    throw;
                }
            }
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
            // TODO: Actually a much more complex implementation of QeryInfoKeyA,
            // traversing through all values and handling strings in a special way
            // is required for exact MaxValueLen value calculation taking
            // into account unicode->ansi conversion.
            // For now we return a bigger value, still enough to allocate buffers
            // (length of unicode values is always larger than length of ansi ones).
            using (Uni2AnsiConverter classConverter =
                   new Uni2AnsiConverter(new Data(lpClass, lpcClass, Data.CountIn.Chars),
                       DoUni2AnsiConversion))
            {
                OffRegHive.ConvertException(() =>
                    key_.QueryInfoUnmanaged(
                        classConverter.UnicodeStr, lpcClass,
                        lpcSubKeys,
                        lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen,
                        lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime));
                classConverter.Convert();
            }
        }
    }
}
