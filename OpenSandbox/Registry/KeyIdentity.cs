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
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

using OpenSandbox.Logging;

namespace OpenSandbox.Registry
{
    // Identity uses ntdll.dll paths and predefined registry base keys
    // This means that wow64 keys are explicitly present in paths
    internal class KeyIdentity
    {
        private IntPtr baseKey_; // One of the predefined registry keys HKEY_*
        // Full path to this key except HKEY_* base key name.
        // Path contains Wow6432Node if it points to 32bit branch of registry on 64 bit machine.
        // It can't be an empty string, but it can be null.
        private string systemPathRelativeToBaseKey_;
        private static Dictionary<int, string> predefinedPaths_ =
            new Dictionary<int, string>();

        static KeyIdentity()
        {
            foreach (int key in Enum.GetValues(typeof(Win32Api.RegPredefinedKeys)))
            {
                predefinedPaths_.Add(key, Enum.GetName(typeof(Win32Api.RegPredefinedKeys), key));
            }
        }

        private struct BaseKeyAndPath
        {
            public Win32Api.RegPredefinedKeys BaseKey;
            public string Path;
        }

        private static List<BaseKeyAndPath> Wow64RedirectedPaths =
            new List<BaseKeyAndPath>
        {
            new BaseKeyAndPath {BaseKey = Win32Api.RegPredefinedKeys.HKEY_CLASSES_ROOT, Path = null},
            // More deep paths first to be handled first
            new BaseKeyAndPath {BaseKey = Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER, Path = @"software\classes"},
            new BaseKeyAndPath {BaseKey = Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER, Path = @"software"},
            new BaseKeyAndPath {BaseKey = Win32Api.RegPredefinedKeys.HKEY_LOCAL_MACHINE, Path = @"software\classes"},
            new BaseKeyAndPath {BaseKey = Win32Api.RegPredefinedKeys.HKEY_LOCAL_MACHINE, Path = @"software"}
            // TODO: what about wow64 within HKEY_USERS differen than the current one?
        };

        // precondition: Called only for "default" identities not containing wow6432node
        private string GetWow64RedirectedPath()
        {
            foreach (BaseKeyAndPath bkap in Wow64RedirectedPaths)
            {
                if (baseKey_ == (IntPtr)bkap.BaseKey)
                {
                    if (bkap.Path == null)
                    {
                        return CombinePaths(Wow6432Node, systemPathRelativeToBaseKey_);
                    }
                    if (systemPathRelativeToBaseKey_ != null &&
                        systemPathRelativeToBaseKey_.StartsWith(bkap.Path, StringComparison.CurrentCultureIgnoreCase))
                    {
                        return bkap.Path + @"\" + Wow6432Node + systemPathRelativeToBaseKey_.Remove(0, bkap.Path.Length);
                    }
                }
            }
            return systemPathRelativeToBaseKey_;
        }

        internal KeyIdentity(KeyIdentity parentIdentity, Win32Api.RegWow64Options wowOptions, string subKey)
        {
            // Which are the options:
            // 0. The process is either 32 or 64 bit.
            // 1. ParentIdentity is either 32 or 64 or it is too high level key so path does not yet include
            // Wow6432Node, this means "Default" flags.
            // 2. wowOptions is either 32, 64

            // It can be that subKey == null, parentIdentity uses "default" flags,
            // in this case we have to decide add Wow6432Node...
            // and because of so many places where it may appear...
            // better to make some system function do that for us.

            // Resulting wowOptions are assigned wowOptions specified in the function call
            // because as per msdn they MUST be equal to those used in previous calls for opening
            // parent keys.

            // Creating default (32 bit on 32bit OS, 64 bit on 64 bit OS) identity to get canonized path
            KeyIdentity defaultIdentity = new KeyIdentity(parentIdentity.baseKey_, CombinePaths(parentIdentity.GetRegPath(), subKey));
            baseKey_ = defaultIdentity.baseKey_; // Canonized base key
            // Taking care of Wow64 if we are on 64 bit OS after we canonized the path and base key.
            systemPathRelativeToBaseKey_ = defaultIdentity.AdjustWow64PathIfNeeded(wowOptions);
        }

        // Ctor for creating identity of predefined of windows base keys (OpenCurrentUser, OpenUserClassesRoot)
        internal KeyIdentity(IntPtr nativeBaseHKey)
            : this(new KeyIdentity(nativeBaseHKey, null), Win32Api.RegWow64Options.None, null)
        {
        }

        // precondition: Called only for "default" identities not containing wow6432node
        private string AdjustWow64PathIfNeeded(Win32Api.RegWow64Options wowOptions)
        {
            if (Utils.Is64BitOperatingSystem)
            {
                if (wowOptions == Win32Api.RegWow64Options.None)
                    // Actually for now (May 2013) we can run only in 32bit process, but may be in the future...
                    wowOptions = Utils.Is64BitProcess ? Win32Api.RegWow64Options.KEY_WOW64_64KEY : Win32Api.RegWow64Options.KEY_WOW64_32KEY;

                // Now wowOptions specify definetly, which branch of registry to access
                if (wowOptions == Win32Api.RegWow64Options.KEY_WOW64_32KEY)
                    return GetWow64RedirectedPath();
            }
            return systemPathRelativeToBaseKey_;
        }

        // Ctor privately used to initialize fields directly
        private KeyIdentity(IntPtr baseKey, string path)
        {
            baseKey_ = baseKey;
            systemPathRelativeToBaseKey_ = path;
            CanonizeIdentity();
            // Not calling wow64 adjustment because path already contains wow6432node if it is needed
        }

        public override bool Equals(object obj)
        {
            return obj is KeyIdentity && this == (KeyIdentity)obj;
        }

        private string systemPathRelativeToBaseKeyLwr_;

        public override int GetHashCode()
        {
            if (systemPathRelativeToBaseKey_ == null) return baseKey_.GetHashCode();
            if (systemPathRelativeToBaseKeyLwr_ == null)
            {
                systemPathRelativeToBaseKeyLwr_ = systemPathRelativeToBaseKey_.ToLower();
            }
            return baseKey_.GetHashCode() ^ systemPathRelativeToBaseKeyLwr_.GetHashCode();
        }

        public static bool operator ==(KeyIdentity first, KeyIdentity second)
        {
            if (((object)first == null) || ((object)second == null))
            {
                return ((object)first == null) == ((object)second == null);
            }
            return first.BaseKey == second.BaseKey && string.Compare(first.NtPath, second.NtPath, ignoreCase: true) == 0;
        }

        public static bool operator !=(KeyIdentity first, KeyIdentity second)
        {
            return !(first == second);
        }

        internal static string CombinePaths(string basePath, string subKey)
        {
            if (basePath == null)
            {
                return subKey;
            }
            if (subKey == null)
            {
                return basePath;
            }
            // TODO: handle the case of empty-string subKey.
            // see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724897%28v=vs.85%29.aspx
            // lpSubKey description. Empty-string subkey has different meanings depending on baseKey.
            return basePath + @"\" + subKey;
        }

        // This function is solely called from the private constructor
        // so that it is assummed that non-private constructors operate canonized paths.
        private void CanonizeIdentity()
        {
            // TODO: create a safe set of operations comparing IntPtr to predefined keys
            // without tons of unsafe conversions to int and back. Or simply make
            // all predefined paths int64
            if (!Enum.IsDefined(typeof(Win32Api.RegPredefinedKeys), (int)baseKey_))
            {
                KeyIdentity baseKeyIdentity;
                if (!GetNativeHKeyName(baseKey_, out baseKeyIdentity))
                {
                    throw new InvalidHandleException();
                }
                // TODO: isn't it a resource leak? baseKey_ contains valid handle
                baseKey_ = baseKeyIdentity.baseKey_;
                systemPathRelativeToBaseKey_ = CombinePaths(baseKeyIdentity.systemPathRelativeToBaseKey_, systemPathRelativeToBaseKey_);
            }
            if ((Int64)baseKey_ == (Int64)Win32Api.RegPredefinedKeys.HKEY_USERS &&
                systemPathRelativeToBaseKey_ != null)
            {
                WindowsIdentity id = WindowsIdentity.GetCurrent();
                string userClassesPrefix = id.User.Value.ToUpper() + "_CLASSES";
                if (systemPathRelativeToBaseKey_.ToUpper().StartsWith(userClassesPrefix))
                {
                    baseKey_ = (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CLASSES_ROOT;
                    systemPathRelativeToBaseKey_ = RemovePrefix(systemPathRelativeToBaseKey_, userClassesPrefix.Length);
                }
                else if (systemPathRelativeToBaseKey_.ToUpper().StartsWith(id.User.Value.ToUpper()))
                {
                    baseKey_ = (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER;
                    systemPathRelativeToBaseKey_ = RemovePrefix(systemPathRelativeToBaseKey_, id.User.Value.Length);
                }
            }
        }

        internal IntPtr BaseKey { get { return baseKey_; } }

        private const string Wow6432Node = "Wow6432Node";

        private static Regex Wow6432NodeRegex = new Regex(@"\\" + Wow6432Node, RegexOptions.IgnoreCase);

        // Path relative to base key for Reg* functions layer
        // precondition (class invariant): systemPathRelativeToBaseKey_ contains 0..1 wow6332node elements.
        internal string GetRegPath()
        {
            if (!Utils.Is64BitOperatingSystem) return systemPathRelativeToBaseKey_;
            if (systemPathRelativeToBaseKey_ == null) return null;
            if (string.Compare(systemPathRelativeToBaseKey_, Wow6432Node, ignoreCase: true) == 0) return null;
            if (systemPathRelativeToBaseKey_.StartsWith(Wow6432Node + @"\", StringComparison.CurrentCultureIgnoreCase))
            {
                return systemPathRelativeToBaseKey_.Remove(0, Wow6432Node.Length + 1);
            }
            // Not wrapping string to replace except backslash into any special regex symbols because
            // we assume it contains only letters and digits ("wow6432node").
            return Wow6432NodeRegex.Replace(systemPathRelativeToBaseKey_, "");
        }

        internal Win32Api.RegWow64Options GetWow64Mode()
        {
            if (!Utils.Is64BitOperatingSystem) return Win32Api.RegWow64Options.None;
            if (systemPathRelativeToBaseKey_ != null &&
                systemPathRelativeToBaseKey_.IndexOf(Wow6432Node, StringComparison.CurrentCultureIgnoreCase) >= 0)
            {
                return Win32Api.RegWow64Options.KEY_WOW64_32KEY;
            }
            return Win32Api.RegWow64Options.KEY_WOW64_64KEY;
        }

        // Path relative to base key for Nt* functions layer
        // and for offreg hive
        internal string NtPath { get { return systemPathRelativeToBaseKey_; } }

        internal static string UknownHKeyStr(IntPtr hKey)
        {
            return "<unknown:" + ((int)hKey).ToString("X") + ">";
        }

        internal static bool IsPredefined(IntPtr hKey)
        {
            return predefinedPaths_.ContainsKey((int)hKey);
        }

        public override string ToString()
        {
            string basePath;
            int baseKey = (int)baseKey_;
            if (IsPredefined(baseKey_))
            {
                basePath = predefinedPaths_[baseKey];
            }
            else
            {
                basePath = UknownHKeyStr(baseKey_);
            }
            return CombinePaths(basePath, systemPathRelativeToBaseKey_);
        }

        private static Dictionary<string, IntPtr> HKeySysNameMappings =
            new Dictionary<string, IntPtr>
        {
            {@"\registry\machine", (IntPtr)Win32Api.RegPredefinedKeys.HKEY_LOCAL_MACHINE},
            {@"\registry\user", (IntPtr)Win32Api.RegPredefinedKeys.HKEY_USERS}
        };

        private static bool GetNativeHKeyName(IntPtr hKey, out KeyIdentity identity)
        {
            identity = null;
            uint cbData;
            int result = Win32Api.NtQueryKey(hKey,
                Win32Api.KeyInformationClass.KeyNameInformation,
                IntPtr.Zero, 0, out cbData);
            if (result != (int)Win32Api.Status.STATUS_BUFFER_TOO_SMALL)
            {
                DebugLogger.WriteLine("Error querying key name {0}", result);
                return false;
            }
            using (HGlobalPtr pData = new HGlobalPtr(cbData))
            {
                result = Win32Api.NtQueryKey(hKey,
                    Win32Api.KeyInformationClass.KeyNameInformation,
                    pData.Ptr, cbData, out cbData);
                if (result != 0)
                {
                    DebugLogger.WriteLine("Error querying key name {0}", result);
                    return false;
                }
                cbData = (uint)Marshal.ReadInt32(pData.Ptr);
                string name = Marshal.PtrToStringUni(
                    (IntPtr)(pData.Ptr.ToInt64() + Marshal.SizeOf(typeof(uint))),
                    (int)cbData / sizeof(char));

                foreach (KeyValuePair<string, IntPtr> m in HKeySysNameMappings)
                {
                    if (name.StartsWith(m.Key, StringComparison.CurrentCultureIgnoreCase))
                    {
                        identity = new KeyIdentity(m.Value, RemovePrefix(name, m.Key.Length));
                        return true;
                    }
                }
                DebugLogger.WriteLine("Can't interpret key name {0}", name);
            }
            return false;
        }

        // Does not check if the path really begins with the prefix
        private static string RemovePrefix(string path, int prefixLength)
        {
            if (path.Length <= prefixLength) return null;
            return path.Remove(0, prefixLength + 1);
        }

        private string GetSystemBasePath()
        {
            return GetSystemBasePath(baseKey_);
        }

        internal static string GetSystemBasePath(IntPtr baseKey)
        {
            foreach (KeyValuePair<string, IntPtr> m in HKeySysNameMappings)
            {
                if (baseKey == m.Value)
                {
                    return m.Key;
                }
            }
            WindowsIdentity id = WindowsIdentity.GetCurrent();
            if (baseKey == (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CLASSES_ROOT)
            {
                return @"\registry\user\" + id.User.Value.ToUpper() + "_Classes";
            }
            if (baseKey == (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER)
            {
                return @"\registry\user\" + id.User.Value.ToUpper();
            }
            if (baseKey == (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CURRENT_CONFIG)
            {
                return @"\registry\machine\SYSTEM\CurrentControlSet\Hardware Profiles\Current";
            }
            throw new InvalidHandleException();
        }

        internal string GetSystemPath()
        {
            return CombinePaths(GetSystemBasePath(), NtPath);
        }

        internal static bool PartitionPath(string path, out string parentPath, out string subkey)
        {
            int pos = path.LastIndexOf('\\');
            if (pos == -1)
            {
                parentPath = null;
                subkey = path;
                return false;
            }
            parentPath = path.Substring(0, pos);
            subkey = path.Substring(pos + 1);
            return true;
        }

        internal string[] SplitPath()
        {
            if (systemPathRelativeToBaseKey_ == null)
            {
                return new string[] {};
            }
            return systemPathRelativeToBaseKey_.Split('\\');
        }

        internal static KeyIdentity Build(IntPtr baseKey, string[] subkeys, int levels)
        {
            return new KeyIdentity(baseKey,
                levels <= 0 ? null : string.Join(@"\", subkeys, 0, levels));
        }

        static string[] SYSTEM_PREFIXES_LW = new string[] {
            @"software\wow6432node\microsoft\windows\currentversion\internet settings\5.0\cache",
            @"software\microsoft\windows\currentversion\internet settings\5.0\cache",
            @"system\currentcontrolset\services\winsock2"
        };

        internal bool IsSystemKey()
        {
            if (systemPathRelativeToBaseKey_ == null) return false;
            foreach (string prefix in SYSTEM_PREFIXES_LW)
            {
                if (systemPathRelativeToBaseKey_.StartsWith(prefix, StringComparison.CurrentCultureIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
