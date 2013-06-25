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
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.ComponentModel;
using OpenSandbox.Logging;

namespace OpenSandbox.Registry
{
    [Serializable]
    internal class FileLockException : ApplicationException
    {
        internal FileLockException(string message, Exception inner)
            : base(message, inner)
        { }
        protected FileLockException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }

    internal class FileLock : DisposableBase
    {
        private FileStream stream_;

        internal FileLock(string filename)
        {
            Lock(filename);
        }

        private void Lock(string filename)
        {
            try
            {
                stream_ = new FileStream(filename, FileMode.Create, FileAccess.ReadWrite,
                    FileShare.None);
            }
            catch (IOException ex)
            {
                throw new FileLockException("Can't create a file lock", ex);
            }
        }

        private void Unlock()
        {
            if (stream_ != null)
            {
                stream_.Close();
                try
                {
                    File.Delete(stream_.Name);
                }
                catch (Exception) { }
                stream_ = null;
            }
        }

        protected override void DisposeUnmanaged()
        {
            Unlock();
        }
    }

    internal class OffRegHive : DisposableBase, IKeyImplOpenFactory
    {
        private KeyDisposition disposition_;
        private string path_;
        private FileLock fileLock_;
//        private IntPtr hive_;
        private OffregLib.OffregHive hive_;
        private bool readOnly_;
        private bool modified_ = false;

        internal const string TMP_SAVE_SUFFIX = ".tmp";

        internal OffRegHive(KeyDisposition disposition, string regHivePath,
            bool readOnly=true)
        {
            disposition_ = disposition;
            path_ = regHivePath;
            readOnly_ = readOnly;
            // We need to lock the specified path so that nobody can open it
            // until we close it, otherwise there might be conflicts in
            // save operations
            fileLock_ = new FileLock(regHivePath + ".lock");
            try
            {
                OpenOrCreateHive(regHivePath, !readOnly);
            }
            catch (Exception)
            {
                fileLock_.Dispose();
                throw;
            }
        }

        internal void MarkAsModified()
        {
            modified_ = true;
        }

        internal static void ConvertException(Win32Exception.Operation operation)
        {
            try
            {
                operation();
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                throw Win32Exception.Create(e.NativeErrorCode);
            }
        }

        internal static int CatchException(Win32Exception.Operation operation)
        {
            try
            {
                operation();
                return 0;
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                return e.NativeErrorCode;
            }
        }

        private void OpenOrCreateHive(string offRegHivePath, bool createIfNotExists)
        {
            try
            {
                ConvertException(() => hive_ = OffregLib.OffregHive.Open(offRegHivePath));
            }
            catch (FileNotFoundException)
            {
                if (!createIfNotExists)
                {
                    throw;
                }
                ConvertException(() => hive_ = OffregLib.OffregHive.Create());
            }
        }

        internal KeyDisposition Disposition { get { return disposition_; } }

        protected override void DisposeUnmanaged()
        {
            if (hive_ != null)
            {
                if (!readOnly_)
                {
                    // Trying to save in any case
                    try
                    {
                        Save();
                    }
                    catch { }
                }

                cacheForDeletedMarks_.Dispose();
                cacheForDeletedMarks_ = null;

                // Closing
                hive_.Close();
                hive_ = null;

                fileLock_.Dispose();
                fileLock_ = null;
            }
        }

        public bool TryOpen(KeyIdentity identity, KeySecurity samDesired, out IKeyImpl openedImpl)
        {
            OffRegKey offregKey;
            bool result = OffRegKey.TryOpen(this, hive_, identity, out offregKey);
            openedImpl = offregKey;
            return result;
        }

        internal IKeyImpl Create(KeyIdentity identity, string lpClass,
            Win32Api.RegOption dwOptions, IntPtr lpSecurityDescriptor,
            IntPtr lpdwDisposition)
        {
            return new OffRegKey(this, hive_, identity, lpClass, dwOptions,
                lpSecurityDescriptor, lpdwDisposition);
        }

        internal void Save()
        {
            if (!modified_) return;
            // We are locking among threads, because file lock
            // already keeps us safe among processes
            DebugLogger.WriteLine("Saving offreg hive...");
            try
            {
                lock (this)
                {
                    // Double check under lock
                    if (!modified_) return;

                    string tempPath = path_ + TMP_SAVE_SUFFIX;
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch (Exception) { }
                    ConvertException(() =>
                        hive_.SaveHive(tempPath,
                            unchecked((uint)Environment.OSVersion.Version.Major),
                            unchecked((uint)Environment.OSVersion.Version.Minor)));
                    File.Delete(path_);
                    File.Move(tempPath, path_);
                    modified_ = false;
                }
                DebugLogger.WriteLine("Saving offreg hive... done");
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine("Saving offreg hive... exception " + ex.ToString());
                throw;
            }
        }

        // We don't deallocate them for now because we don't care about resources
        // after sandbox is unloaded
        [ThreadStatic]
        HGlobalPtr IMAD_pData_ = new HGlobalPtr(Marshal.SizeOf(typeof(int)));
        [ThreadStatic]
        HGlobalPtr IMAD_pcbData_ = new HGlobalPtr(Marshal.SizeOf(typeof(int)));

        internal bool IsMarkedAsDeleted(KeyIdentity existingBase, KeyIdentity identity)
        {
            if (identity.IsSystemKey()) return false;
            try
            {
                    return DoesntExistOrMarkedAsDeleted(existingBase, identity,
                        IMAD_pData_.Ptr, IMAD_pcbData_.Ptr) == DoesntExistOrMarkedAsDeletedState.MarkedAsDeleted;
            }
            catch (FileNotFoundException)
            {
                // We don't know anything about the key, so it was not marked as deleted
                return false;
            }
            catch (Win32Exception ex)
            {
                DebugLogger.WriteLine("IsDeleted exception " + ex.ToString());
                throw;
            }
        }

        private const string DELETED_PREFIX = "OpenSandboxDeleted_";

        private KeyImplCache cacheForDeletedMarks_ = new KeyImplCache();

        private enum DoesntExistOrMarkedAsDeletedState { Exists, DoesntExist, MarkedAsDeleted };

        private KeySecurity cacheSecurity_ = new KeySecurity(Win32Api.KeySecurity.KEY_READ);

        private DoesntExistOrMarkedAsDeletedState DoesntExistOrMarkedAsDeleted(KeyIdentity existingBase, KeyIdentity identity,
            IntPtr allocatedpData, IntPtr allocatedpcbData)
        {
            string[] subkeys = identity.SplitPath();
            int existingLevels, nonRemovableLevels;
            CalcNonRemovableLevels(existingBase, identity, out existingLevels, out nonRemovableLevels);
            if (subkeys.Length <= nonRemovableLevels)
            {
                return DoesntExistOrMarkedAsDeletedState.Exists;
            }

            for (int level = existingLevels; level < subkeys.Length; level++)
            {
                KeyIdentity curLevelIdentity = KeyIdentity.Build(identity.BaseKey, subkeys, level);
                KeyImplHolder holder;
                lock (this)
                {
                    IKeyImpl keyImpl = null;
                    
                    if (level <= nonRemovableLevels)
                    {
                        keyImpl = cacheForDeletedMarks_.TryGet(curLevelIdentity, KeyDisposition.DIFF_HIVE, cacheSecurity_);
                    }
                    if (keyImpl != null)
                    {
                        holder = new NotOwningKeyImplHolder(keyImpl);
                    }
                    else
                    {
                        OffregLib.OffregKey key;
                        OffregLib.Win32Result result;
                        if (!hive_.Root.TryOpenSubKey(OffRegKey.GetMainOffRegPath(curLevelIdentity), out key, out result))
                        {
                            return DoesntExistOrMarkedAsDeletedState.DoesntExist;
                        }
                        holder = new KeyImplHolder(new OffRegKey(this, key, curLevelIdentity));
                        if (level <= nonRemovableLevels)
                        {
                            // Adding to cache only the lowest, non removable level
                            holder = cacheForDeletedMarks_.Add(
                                curLevelIdentity, KeyDisposition.DIFF_HIVE,
                                holder);
                        }
                    }
                }
                using (holder)
                {
                    Marshal.WriteInt32(allocatedpcbData, Marshal.SizeOf(typeof(int)));
                    if (holder.GetKeyImpl().TryQueryValue(
                            DELETED_PREFIX + subkeys[level],
                            IntPtr.Zero, IntPtr.Zero, allocatedpData, allocatedpcbData))
                    {
                        if (Marshal.ReadInt32(allocatedpcbData) == Marshal.SizeOf(typeof(int)) &&
                            Marshal.ReadInt32(allocatedpData) != 0)
                        {
                            // There is a special value marking key as deleted
                            return DoesntExistOrMarkedAsDeletedState.MarkedAsDeleted;
                        }
                    }
                }
            }
            return DoesntExistOrMarkedAsDeletedState.Exists;
        }

        private static Dictionary<long, List<KeyValuePair<string, int>>> nonRemovableLevelsPerBaseKey_ =
            new Dictionary<long, List<KeyValuePair<string, int>>>
        {
            {(Int64)Win32Api.RegPredefinedKeys.HKEY_CLASSES_ROOT,
                new List<KeyValuePair<string, int>> {
                    new KeyValuePair<string, int>("CLSID", 1),
                    new KeyValuePair<string, int>("Interface", 1),
                    new KeyValuePair<string, int>("TypeLib", 1),
                    new KeyValuePair<string, int>(null, 0)}
            },
            {(Int64)Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER,
                new List<KeyValuePair<string, int>> {
                    new KeyValuePair<string, int>(@"Software\classes\Wow6432Node\Interface", 4),
                    new KeyValuePair<string, int>(@"Software\classes\Interface", 3),
                    new KeyValuePair<string, int>(@"Software\classes\Wow6432Node\TypeLib", 4),
                    new KeyValuePair<string, int>(@"Software\classes\TypeLib", 3),
                    new KeyValuePair<string, int>(@"Software\Wow6432Node\Microsoft\Windows\CurrentVersion", 5),
                    new KeyValuePair<string, int>(@"Software\Microsoft\Windows\CurrentVersion", 4),
                    new KeyValuePair<string, int>(@"Software\Wow6432Node\Microsoft", 3),
                    new KeyValuePair<string, int>(@"Software\Microsoft", 2),
                    new KeyValuePair<string, int>(null, 1)
                }
            },
            {(Int64)Win32Api.RegPredefinedKeys.HKEY_LOCAL_MACHINE,
                new List<KeyValuePair<string, int>> {
                    new KeyValuePair<string, int>(@"System\CurrentControlSet\Services\WinSock2\Parameters", 5),
                    new KeyValuePair<string, int>(@"System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", 6),
                    new KeyValuePair<string, int>(@"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion", 5),
                    new KeyValuePair<string, int>(@"Software\Microsoft\Windows NT\CurrentVersion", 4),
                    new KeyValuePair<string, int>(null, 1)
                }
            },
            {(Int64)Win32Api.RegPredefinedKeys.HKEY_USERS,
                new List<KeyValuePair<string, int>> {new KeyValuePair<string, int>(null, 2)}}
        };

        internal static void CalcNonRemovableLevels(KeyIdentity existingBase, KeyIdentity identity,
            out int existing, out int nonRemovable)
        {
            existing = 0;
            if (existingBase != null && existingBase.BaseKey == identity.BaseKey)
            {
                existing = existingBase.SplitPath().Length;
            }
            if (!nonRemovableLevelsPerBaseKey_.ContainsKey((long)identity.BaseKey))
            {
                throw new FileNotFoundException();
            }
            List<KeyValuePair<string, int>> nonRemovableLevelsPerPrefix = nonRemovableLevelsPerBaseKey_[(long)identity.BaseKey];
            foreach (KeyValuePair<string, int> keyValue in nonRemovableLevelsPerPrefix)
            {
                if (keyValue.Key == null)
                {
                    nonRemovable = keyValue.Value;
                    existing = Math.Max(existing, nonRemovable);
                    return;
                }
                if (identity.NtPath == null) continue;
                // Optimized checking if NtPath begins with keyValue.Key
                if (identity.NtPath.StartsWith(keyValue.Key, StringComparison.CurrentCultureIgnoreCase) &&
                    (identity.NtPath.Length == keyValue.Key.Length || identity.NtPath[keyValue.Key.Length] == '\\'))
                {
                    nonRemovable = keyValue.Value;
                    existing = Math.Max(existing, nonRemovable);
                    return;
                }
            }
            nonRemovable = 0;
            return;
        }

        internal void MarkKeyAsDeleted(KeyIdentity identity)
        {
            try
            {
                string[] subkeys = identity.SplitPath();
                int existingLevels, nonRemovableLevels;
                CalcNonRemovableLevels(null, identity, out existingLevels, out nonRemovableLevels);
                if (subkeys.Length <= nonRemovableLevels)
                {
                    // We can't mark root keys as deleted
                    return;
                }
                using (HGlobalPtr pData = new HGlobalPtr(Marshal.SizeOf(typeof(int))))
                {
                    Marshal.WriteInt32(pData.Ptr, 1);
                    // Conciously suppressing errors
                    OffRegKey key = null;
                    try
                    {
                        key = new OffRegKey(this, hive_,
                            KeyIdentity.Build(identity.BaseKey, subkeys, subkeys.Length - 1), null,
                            Win32Api.RegOption.REG_OPTION_NON_VOLATILE, IntPtr.Zero,
                            IntPtr.Zero);
                        key.SetValue(DELETED_PREFIX + subkeys[subkeys.Length - 1],
                            Win32Api.RegValueType.REG_DWORD,
                            pData.Ptr, Marshal.SizeOf(typeof(int)));
                    }
                    catch (Win32Exception)
                    {
                        // Suppressing errors because there might be access issues
                        // or may be other stuff
                        if (key != null) key.Close();
                    }
                }
            }
            catch (FileNotFoundException)
            {
                // We don't know anything about the key, so we can't mark it as deleted
                return;
            }
        }
    }
}
