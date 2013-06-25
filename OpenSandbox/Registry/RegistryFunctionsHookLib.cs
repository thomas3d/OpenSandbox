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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

using EasyHook;
using Microsoft.Win32;
using OpenSandbox.Logging;

namespace OpenSandbox.Registry
{
    /// <summary>
    /// The class manages hooking registry API functions.
    /// </summary>
    /// It is derived from Win32Api because extensively uses imported
    /// functions so this allows to avoid using Win32Api. prefix.
    internal class RegistryFunctionsHookLib : Win32Api
    {
        // TODO: this and other *HookLib static constructors
        // are called not only in the target process
        // but also in the host process, which is not needed.
        // Static constructor does some expensive operations
        // like binding types to pinvokes, creating new types.
        // Put this stuff into special static function instead of
        // static constructors.
        // TODO: register functions by iterating over this class methods,
        // to avoid a need to specify new function in several places
        // This possibly can be done by associating delegates to methods using attribute
        // if attribute can accept arguments of type 'Delegate'.
        private static Hooks hooks_ = new Hooks(new Delegate[]
        {
            new NtOpenKey_Delegate(NtOpenKey_Hooked),
            new NtQueryKey_Delegate(NtQueryKey_Hooked),

            new RegCloseKey_Delegate(RegCloseKey_Hooked),
            new RegConnectRegistry_Delegate(RegConnectRegistry_Hooked),
            new RegCreateKey_Delegate(RegCreateKey_Hooked),
            new RegCreateKeyEx_Delegate(RegCreateKeyEx_Hooked),
            new RegDeleteKey_Delegate(RegDeleteKey_Hooked),

            new RegDeleteValue_Delegate(RegDeleteValue_Hooked),
            new RegEnumKey_Delegate(RegEnumKey_Hooked),
            new RegEnumKeyEx_Delegate(RegEnumKeyEx_Hooked),
            new RegEnumValue_Delegate(RegEnumValue_Hooked),
            new RegFlushKey_Delegate(RegFlushKey_Hooked),
            new RegGetKeySecurity_Delegate(RegGetKeySecurity_Hooked),
            
            new RegLoadKey_Delegate(RegLoadKey_Hooked),
            new RegNotifyChangeKeyValue_Delegate(RegNotifyChangeKeyValue_Hooked),
            new RegOpenCurrentUser_Delegate(RegOpenCurrentUser_Hooked),
            new RegOpenKey_Delegate(RegOpenKey_Hooked),
            new RegOpenKeyEx_Delegate(RegOpenKeyEx_Hooked),
            
            new RegOpenUserClassesRoot_Delegate(RegOpenUserClassesRoot_Hooked),
            new RegOverridePredefKey_Delegate(RegOverridePredefKey_Hooked),
            new RegQueryInfoKey_Delegate(RegQueryInfoKey_Hooked),
            new RegQueryMultipleValues_Delegate(RegQueryMultipleValues_Hooked),

            new RegQueryValue_Delegate(RegQueryValue_Hooked),
            new RegQueryValueEx_Delegate(RegQueryValueEx_Hooked),
            new RegReplaceKey_Delegate(RegReplaceKey_Hooked),
            new RegRestoreKey_Delegate(RegRestoreKey_Hooked),
            new RegSaveKey_Delegate(RegSaveKey_Hooked),
            new RegSaveKeyEx_Delegate(RegSaveKeyEx_Hooked),
            
            new RegSetKeySecurity_Delegate(RegSetKeySecurity_Hooked),
            new RegSetValue_Delegate(RegSetValue_Hooked),
            new RegSetValueEx_Delegate(RegSetValueEx_Hooked),
            new RegUnLoadKey_Delegate(RegUnLoadKey_Hooked),

            // Even though these functions are not present in Windows XP
            // they will be just ignored on XP, w/o any error
            new RegCopyTree_Delegate(RegCopyTree_Hooked),
            new RegCreateKeyTransacted_Delegate(RegCreateKeyTransacted_Hooked),
            new RegDeleteKeyTransacted_Delegate(RegDeleteKeyTransacted_Hooked),
            new RegDeleteKeyValue_Delegate(RegDeleteKeyValue_Hooked),
            new RegDeleteTree_Delegate(RegDeleteTree_Hooked),
            new RegOpenKeyTransacted_Delegate(RegOpenKeyTransacted_Hooked),
            new RegSetKeyValue_Delegate(RegSetKeyValue_Hooked),

            // These functions are present in Windows XP 64 and above
            new RegDeleteKeyEx_Delegate(RegDeleteKeyEx_Hooked),
            new RegDisableReflectionKey_Delegate(RegDisableReflectionKey_Hooked),
            new RegEnableReflectionKey_Delegate(RegEnableReflectionKey_Hooked),
            new RegGetValue_Delegate(RegGetValue_Hooked),
            new RegQueryReflectionKey_Delegate(RegQueryReflectionKey_Hooked)
        });
        internal static Hooks Hooks { get { return hooks_; } }


        // This function is exception-safe and does not throw any exceptions
        private static void RegLogging(IHookHolderAndCallback hhac, FunctionIdentity identity,
            string format, params object[] args)
        {
            if (!DebugLogger.DoLogging) return;
            try
            {
                Injection injection = (Injection)hhac;
                // change pointers to strings
                if (injection.VirtualRegistry != null)
                {
                    for (int i = 0; i < args.Length; i++)
                    {
                        if (args[i] is System.IntPtr)
                            args[i] = injection.VirtualRegistry.GetKeyPath((IntPtr)args[i]);
                        else if (args[i] is System.UIntPtr)
                            // TODO: to avoid overflow exception, the conversion below
                            // should be put into unchecked()
                            // but for now it is used only when not implemented hooks
                            // are called which helps to identify them, so we leave it as it is.
                            args[i] = injection.VirtualRegistry.GetKeyPath(
                                unchecked((IntPtr)(long)(ulong)(UIntPtr)args[i]));
                    }
                }

                HookLogging.DefaultLogging(injection, identity, format, args);
            }
            catch (Exception ex)
            {
                try
                {
                    Injection injection = (Injection)hhac;
                    HookLogging.DefaultLogging(injection, identity, "Logging exception: " + ex.ToString());
                }
                catch { }
            }
        }

        private static void RegLoggingForNotImplemented(Injection demoInjection, string funcName,
            string format, params object[] args)
        {
            // Adding empty line and prefix for better visibility of such log entries
            RegLogging(demoInjection, new FunctionIdentity(Advapi32DllName, "   NOT IMPLEMENTED: " + funcName), format + "\n", args);
        }

        private static int HookSkeleton(HookClosure<int> closure, VoidOperation operation, string format, params object[] args)
        {
            return new HookContext<int>(closure,
                helper => {
                    if (((Injection)helper.HookHolderAndCallback).VirtualRegistry == null)
                        return helper.CallNative(forceLogging: true);
                    operation((Injection)helper.HookHolderAndCallback);
                    return 0;
                }, errorCode => errorCode,
                RegLogging,
                format, args).Call();
        }

        internal static int NtOpenKey_Hooked(out IntPtr KeyHandle, uint AccessMask,
            IntPtr ObjectAttributes)
        {
            IntPtr tmpKeyHandle = IntPtr.Zero;
            // HookHelper is used here instead of HookSkeleton to avoid
            // double conversion retcode -> exception -> retcode
            int result = new HookContext<int>(
                func =>
                {
                    IntPtr pUnicodeString = Marshal.ReadIntPtr(ObjectAttributes, 4 + Marshal.SizeOf(typeof(IntPtr)));
                    //Helper.WriteLine("NtOpenKey object attributes: Handle 0x{0} Name {1}",
                    //    ((Int64)Marshal.ReadIntPtr(ObjectAttributes, 4)).ToString("X"),
                    //    (Marshal.ReadIntPtr(pUnicodeString, 4) == IntPtr.Zero) ? null :
                    //        Marshal.PtrToStringUni(Marshal.ReadIntPtr(pUnicodeString, 4),
                    //            Marshal.ReadInt16(pUnicodeString) / sizeof(char)));
                    return ((NtOpenKey_Delegate)func)(out tmpKeyHandle, AccessMask,
                        ObjectAttributes);
                },
                helper => NtOpenKey(out tmpKeyHandle, AccessMask, ObjectAttributes),
                errorCode => errorCode,
                RegLogging, "called around hooks [REG KEY]: {0}.", tmpKeyHandle).Call();
            KeyHandle = tmpKeyHandle;
            return result;
        }

        internal static int NtQueryKey_Hooked(IntPtr KeyHandle,
            KeyInformationClass KeyInformationClass,
            IntPtr KeyInformation, uint Length, out uint ResultLength)
        {
            uint tmpResultLength = 0;
            int result = HookSkeleton(
                func => ((NtQueryKey_Delegate)func)(KeyHandle, KeyInformationClass,
                    KeyInformation, Length, out tmpResultLength),
                injection => injection.VirtualRegistry.GetKey(KeyHandle).NtQueryKey(
                        KeyInformationClass, KeyInformation, Length, out tmpResultLength),
                "[REG KEY]: {0} [Length]: {1}.", KeyHandle, Length);
            ResultLength = tmpResultLength;
            return result;
        }

        class ClosingKey
        {
            private IntPtr hKey_;
            private string strRepr_ = null;

            internal ClosingKey(IntPtr hKey)
            {
                hKey_ = hKey;
            }

            internal void SetStrRepr(string strRepr)
            {
                strRepr_ = strRepr;
            }

            public override string ToString()
            {
                if (strRepr_ != null)
                {
                    return strRepr_;
                }
                return hKey_.ToString();
            }
        }
        /// <summary>
        /// The hook function that is called in response to RegCloseKey API function. 
        /// See MSDN for details.
        /// </summary>
        internal static Int32 RegCloseKey_Hooked(IntPtr hKey)
        {
            ClosingKey ck = new ClosingKey(hKey);
            return HookSkeleton(
                func => ((RegCloseKey_Delegate)func)(hKey),
                injection =>
                {
                    ck.SetStrRepr(injection.VirtualRegistry.GetKeyPath(hKey));
                    injection.VirtualRegistry.CloseKey(hKey);
                }, "[REG KEY]: {0}.", ck);
        }

        /// <summary>
        /// The hook function that is called in response to RegConnectRegistry API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegConnectRegistry_Hooked(
            String lpMachineName, 
            UIntPtr hKey,
            /*ref IntPtr*/ IntPtr phkResult)

        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegConnectRegistryFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [MACHINE NAME]: {1}.", hKey, lpMachineName);
                }
                catch(Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegConnectRegistry(
                    lpMachineName,
                    hKey,
                    phkResult);
            }
            catch(Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegCopyTree API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegCopyTree_Hooked(
            IntPtr hKeySrc,
            String lpSubKey,
            IntPtr hKeyDest)
        {
            int result = HookSkeleton(
                func => ((RegCopyTree_Delegate)func)(hKeySrc, lpSubKey, hKeyDest), 
                injection => injection.VirtualRegistry.CopyTree(hKeySrc, lpSubKey, hKeyDest),
                "[KEY SRC]: {0}, [SUBKEY]: {1}, [KEY DEST]: {2}", hKeySrc, lpSubKey, hKeyDest);
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegCreateKey API function. 
        /// See MSDN for details.
        /// Creates the specified registry key. If the key already exists, the function opens it. Note that key names are not case sensitive.
        /// </summary>
        internal static Int32 RegCreateKey_Hooked(
            IntPtr hKey,
            String lpSubKey,
            out IntPtr phkResult)
        {
            IntPtr phkResultCopy = IntPtr.Zero;
            int result = HookSkeleton(
                func => ((RegCreateKey_Delegate)func)(hKey, lpSubKey, out phkResultCopy),
                injection => injection.VirtualRegistry.CreateKey(hKey, lpSubKey, 0,
                    null, 0, Win32Api.KeySecurity.KEY_READ, IntPtr.Zero, out phkResultCopy,
                    IntPtr.Zero), "[PARENT REG KEY]: {0}, [SUB KEY]: {1}.", hKey, lpSubKey);
            phkResult = phkResultCopy;
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegCreateKeyEx API function. 
        /// See MSDN for details.
        /// Creates the specified registry key. If the key already exists, the function opens it. Note that key names are not case sensitive.
        /// </summary>
        internal static Int32 RegCreateKeyEx_Hooked(
            IntPtr hKey,
            String lpSubKey,
            int Reserved,
            String lpClass,
            RegOption dwOptions,
            KeySecurity samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            IntPtr lpdwDisposition)
        {
            Injection callbackObject = (Injection) HookRuntimeInfo.Callback;
            IntPtr phkResultCopy = IntPtr.Zero;
            int result = HookSkeleton(
                func => ((RegCreateKeyEx_Delegate)func)(hKey, lpSubKey, Reserved,
                    lpClass, dwOptions, samDesired, lpSecurityAttributes, out phkResultCopy,
                    lpdwDisposition),
                injection => injection.VirtualRegistry.CreateKey(hKey, lpSubKey, Reserved,
                    lpClass, dwOptions, samDesired, lpSecurityAttributes, out phkResultCopy,
                    lpdwDisposition),
                "[PARENT REG KEY]: {0}, [SUB KEY]: {1}, [CLASS]: {2}.", hKey, lpSubKey, lpClass);
            phkResult = phkResultCopy;
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegCreateKeyTransacted API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegCreateKeyTransacted_Hooked(
            UIntPtr hKey,
            String lpSubKey,
            UInt32 Reserved,
            String lpClass,
            RegOption dwOptions,
            KeySecurity samDesired,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            /*ref IntPtr*/ IntPtr phkResult,
            /*ref RegKeyDisposition*/ IntPtr lpdwDisposition,
            IntPtr hTransaction,
            IntPtr pExtendedParameter)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegCreateKeyTransactedFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[PARENT REG KEY]: {0}, [SUB KEY]: {1}, [CLASS]: {2}.", hKey, lpSubKey, lpClass);
                }
               catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                Int32 retval = RegCreateKeyTransacted(
                    hKey,
                    lpSubKey,
                    Reserved,
                    lpClass,
                    dwOptions,
                    samDesired,
                    lpSecurityAttributes,
                    phkResult,
                    lpdwDisposition,
                    hTransaction,
                    pExtendedParameter);

            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegDeleteKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDeleteKey_Hooked(
            IntPtr hKey,
            String lpSubKey)
        {
            return HookSkeleton(
                func => ((RegDeleteKey_Delegate)func)(hKey, lpSubKey),
                injection => injection.VirtualRegistry.GetKey(hKey).Delete(lpSubKey,
                    RegWow64Options.None, 0),
                "[REG KEY]: {0}\\{1}.", hKey, lpSubKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegDeleteKeyEx API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDeleteKeyEx_Hooked(
            IntPtr hKey,
            String lpSubKey,
            RegWow64Options samDesired,
            int Reserved)
        {
            return HookSkeleton(
                func => ((RegDeleteKeyEx_Delegate)func)(hKey, lpSubKey, samDesired, Reserved),
                injection => injection.VirtualRegistry.GetKey(hKey).Delete(lpSubKey,
                    samDesired, Reserved),
                "[REG KEY]: {0}\\{1}.", hKey, lpSubKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegDeleteKeyTransacted API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDeleteKeyTransacted_Hooked(
            UIntPtr hKey,
            String lpSubKey,
            KeySecurity samDesired,
            UInt32 Reserved,
            IntPtr Transaction,
            IntPtr pExtendedParemeter)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegDeleteKeyTransactedFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}\\{1}.", hKey, lpSubKey);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegDeleteKeyTransacted(
                    hKey,
                    lpSubKey,
                    samDesired,
                    Reserved,
                    Transaction,
                    pExtendedParemeter);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegDeleteKeyValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDeleteKeyValue_Hooked(
            IntPtr hKey,
            string lpSubKey,
            string lpValueName)
        {
            return HookSkeleton(
                func => ((RegDeleteKeyValue_Delegate)func)(hKey, lpSubKey, lpValueName),
                injection => injection.VirtualRegistry.GetKey(hKey).DeleteValue(lpSubKey, lpValueName),
                "[REG KEY]: {0}\\{1}, [VALUE NAME]: {2}.", hKey, lpSubKey, lpValueName);
        }

        /// <summary>
        /// The hook function that is called in response to RegDeleteTree API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDeleteTree_Hooked(
            IntPtr hKey,
            String lpSubKey)
        {
            return HookSkeleton(
                func => ((RegDeleteTree_Delegate)func)(hKey, lpSubKey),
                injection => injection.VirtualRegistry.DeleteTree(hKey, lpSubKey),
                "[REG KEY]: {0}, [SUBKEY]: {1}", hKey, lpSubKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegDeleteValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDeleteValue_Hooked(
            IntPtr hKey,
            string lpValueName)
        {
            return HookSkeleton(
                func => ((RegDeleteValue_Delegate)func)(hKey, lpValueName),
                injection => injection.VirtualRegistry.GetKey(hKey).DeleteValue(null, lpValueName),
                "[REG KEY]: {0}, [VALUE NAME]: {1}.", hKey, lpValueName);
        }

        /// <summary>
        /// The hook function that is called in response to RegDisableReflectionKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegDisableReflectionKey_Hooked(UIntPtr hBase)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegDisableReflectionKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}", hBase);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegDisableReflectionKey(/*(redirect) ? Helper.GetMirrorKey(injection, (int)hBase) : */hBase);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegEnableReflectionKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegEnableReflectionKey_Hooked(UIntPtr hBase)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegEnableReflectionKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}", hBase);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegEnableReflectionKey(/*(redirect) ? Helper.GetMirrorKey(injection, (int)hBase) : */hBase);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegEnumKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegEnumKey_Hooked(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            uint cchName)
        {
            return HookSkeleton(
                func => ((RegEnumKey_Delegate)func)(hKey, dwIndex, lpName,
                    cchName),
                injection =>
                {
                    using (HGlobalPtr lpcchName = new HGlobalPtr(sizeof(int)))
                    {
                        Marshal.WriteInt32(lpcchName.Ptr, unchecked((int)cchName));
                        injection.VirtualRegistry.GetKey(hKey).EnumKey(dwIndex, lpName,
                            lpcchName.Ptr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                            IntPtr.Zero);
                    }
                }, "[REG KEY]: {0}, [INDEX]: {1}.", hKey, dwIndex);
        }

        /// <summary>
        /// The hook function that is called in response to RegEnumKeyEx API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegEnumKeyEx_Hooked(            
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpName,
            /*ref UInt32*/ IntPtr lpcchName,
            IntPtr lpReserved,
            IntPtr lpClass,
            /*ref UInt32*/ IntPtr lpcchClass,
            /*ref FILETIME*/ IntPtr lpftLastWriteTime)
        {
            return HookSkeleton(
                func => ((RegEnumKeyEx_Delegate)func)(hKey, dwIndex, lpName,
                    lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime),
                injection => injection.VirtualRegistry.GetKey(hKey).EnumKey(dwIndex, lpName,
                    lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime),
                "[REG KEY]: {0}, [INDEX]: {1}.", hKey, dwIndex);
        }

        /// <summary>
        /// The hook function that is called in response to RegEnumValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegEnumValue_Hooked(
            IntPtr hKey,
            uint dwIndex,
            IntPtr lpValueName,
            /*ref UInt32*/ IntPtr lpcchValueName,
            IntPtr lpReserved,
            /*ref RegValueType*/ IntPtr lpType,
            IntPtr lpData,
            /*ref UInt32*/ IntPtr lpcbData)
        {
            return HookSkeleton(
                func => ((RegEnumValue_Delegate)func)(hKey, dwIndex, lpValueName,
                    lpcchValueName, lpReserved, lpType, lpData, lpcbData),
                injection => injection.VirtualRegistry.GetKey(hKey).EnumValue(dwIndex,
                    lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData),
                "[REG KEY]: {0}, [INDEX]: {1}.", hKey, dwIndex);
        }

        /// <summary>
        /// The hook function that is called in response to RegFlushKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegFlushKey_Hooked(UIntPtr hKey)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegFlushKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}.", hKey);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegFlushKey(/*(redirect) ? Helper.GetMirrorKey(injection, (int)hKey) : */hKey);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegGetKeySecurity API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegGetKeySecurity_Hooked(
            IntPtr hKey,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr pSecurityDescriptor,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor)
        {
            return HookSkeleton(
                func => ((RegGetKeySecurity_Delegate)func)(hKey, SecurityInformation, pSecurityDescriptor,
                    lpcbSecurityDescriptor),
                injection => injection.VirtualRegistry.GetKey(hKey).GetKeySecurity(SecurityInformation, pSecurityDescriptor,
                    lpcbSecurityDescriptor),
                "[REG KEY]: {0}, [SECURITY INFORMATION]: {1}.", hKey, SecurityInformation);
        }

        /// <summary>
        /// The hook function that is called in response to RegGetValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegGetValue_Hooked(
            IntPtr hKey,
            String lpSubKey,
            String lpValue,
            RegRestrictionFlags dwFlags,
            /*ref UInt32*/ IntPtr pdwType,
            IntPtr pvData,
            /*ref UInt32*/ IntPtr pcbData)
        {
            return HookSkeleton(
                func => ((RegGetValue_Delegate)func)(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData,
                    pcbData),
                injection => injection.VirtualRegistry.GetKey(hKey).GetValue(lpSubKey, lpValue,
                    dwFlags, pdwType, pvData, pcbData),
                "[REG KEY]: {0}, [SUBKEY]: {1}, [VALUE NAME]: {2}.", hKey, lpSubKey, lpValue);
        }

        /// <summary>
        /// The hook function that is called in response to RegLoadKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegLoadKey_Hooked(
            UIntPtr hKey,
            String lpSubKey,
            String lpFile)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegLoadKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: 0x{0}, [SUBKEY]: {1}, [FILE NAME]: {2}.", hKey, lpSubKey, lpFile);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegLoadKey(
                    /*(redirect) ? Helper.GetMirrorKey(injection, (int)hKey) : */hKey,
                    lpSubKey,
                    lpFile);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegNotifyChangeKeyValue API
        /// function. See MSDN for details.
        /// </summary>
        private static int RegNotifyChangeKeyValue_Hooked(
           IntPtr hKey,
           bool watchSubtree,
           REG_NOTIFY_CHANGE notifyFilter,
           IntPtr hEvent,
           bool asynchronous)
        {
            return HookSkeleton(
                func => ((RegNotifyChangeKeyValue_Delegate)func)(
                    hKey, watchSubtree, notifyFilter, hEvent, asynchronous),
                injection => injection.VirtualRegistry.GetKey(hKey).NotifyChangeKeyValue(
                    watchSubtree, notifyFilter, hEvent, asynchronous),
                "[REG KEY]: {0}, [watchSubtree]: {1}, [notifyFilter]: {2}, [asynchronous]: {3}.",
                hKey, watchSubtree, notifyFilter, asynchronous);
        }

        /// <summary>
        /// The hook function that is called in response to RegOpenCurrentUser API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegOpenCurrentUser_Hooked(
            KeySecurity samDesired,
            out IntPtr phkResult)
        {
            IntPtr phkResultCopy = IntPtr.Zero;
            int result = HookSkeleton(
                func => ((RegOpenCurrentUser_Delegate)func)(samDesired, out phkResultCopy),
                injection => injection.VirtualRegistry.OpenCurrentUser(
                    new Registry.KeySecurity(samDesired),
                    out phkResultCopy),
                "[samDesireed]: {0}.", samDesired.ToString());
            phkResult = phkResultCopy;
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegOpenKey API function. 
        /// See MSDN for details.
        /// </summary>
        internal static Int32 RegOpenKey_Hooked(
            IntPtr hKey,
            String lpSubKey,
            out IntPtr phkResult)
        {
            IntPtr phkResultCopy = IntPtr.Zero;
            // TODO: make sure that "default security access mask" as in
            // RegOpenKey description is KEY_READ
            int result = HookSkeleton(
                func => ((RegOpenKey_Delegate)func)(hKey, lpSubKey, out phkResultCopy),
                injection => injection.VirtualRegistry.OpenKey(hKey, lpSubKey, 0,
                    KeySecurity.KEY_READ, out phkResultCopy),
                "[REG KEY]: {0}, [SUBKEY]: {1}. ", hKey, lpSubKey);
            phkResult = phkResultCopy;
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegOpenKeyEx API function. 
        /// See MSDN for details.
        /// </summary>
        internal static Int32 RegOpenKeyEx_Hooked(
            IntPtr hKey,
            String lpSubKey,
            int ulOptions,
            KeySecurity samDesired,
            out IntPtr phkResult)
        {
            IntPtr phkResultCopy = IntPtr.Zero;
            int result = HookSkeleton(
                func => ((RegOpenKeyEx_Delegate)func)(hKey, lpSubKey, ulOptions, samDesired,
                    out phkResultCopy),
                injection => injection.VirtualRegistry.OpenKey(hKey, lpSubKey, ulOptions,
                    samDesired, out phkResultCopy),
                "[REG KEY]: {0}, [SUBKEY]: {1}. [ulOptions]: {2}, [samDesireed]: {3}. ",
                hKey, lpSubKey, ulOptions, samDesired);
            phkResult = phkResultCopy;
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegOpenKeyTransacted API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegOpenKeyTransacted_Hooked(
            UIntPtr hKey,
            String lpSubKey,
            UInt32 ulOptions,
            KeySecurity samDesired,
            /*ref IntPtr*/ IntPtr phkResult,
            IntPtr hTransaction,
            IntPtr ExtendedParameter)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegOpenKeyTransactedFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [SUBKEY]: {1}.", hKey, lpSubKey);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegOpenKeyTransacted(
                    hKey,
                    lpSubKey,
                    ulOptions,
                    samDesired,
                    phkResult,
                    hTransaction,
                    ExtendedParameter);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegOpenUserClassesRoot API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegOpenUserClassesRoot_Hooked(
            IntPtr hToken,
            UInt32 dwOptions,
            KeySecurity samDesired,
            /*ref IntPtr*/ out IntPtr phkResult)
        {
            IntPtr phkResultCopy = IntPtr.Zero;
            int result = HookSkeleton(
                func => ((RegOpenUserClassesRoot_Delegate)func)(
                    hToken, dwOptions, samDesired, out phkResultCopy),
                injection => injection.VirtualRegistry.OpenUserClassesRoot(
                    hToken, dwOptions, new Registry.KeySecurity(samDesired), out phkResultCopy),
                "[dwOptions]: {0} [samDesireed]: {1}.", dwOptions, samDesired.ToString());
            phkResult = phkResultCopy;
            return result;
        }

        /// <summary>
        /// The hook function that is called in response to RegOverridePredefKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegOverridePredefKey_Hooked(
            IntPtr hKey,
            IntPtr hNewHKey)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegOverridePredefKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [NEW REG KEY]: {0}.",
                        injection.VirtualRegistry.GetKeySystemPath(hKey),
                        injection.VirtualRegistry.GetKeySystemPath(hNewHKey));
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

//                Thread.Sleep(1000);
                // ATTENTION: function actually does nothing because it is not implemented
                // but it will work for those calls where hKey == hNewHKey
                return (int)Win32Api.Error.ERROR_SUCCESS;
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegQueryInfoKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegQueryInfoKey_Hooked(
            IntPtr hKey,
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
            return HookSkeleton(
                func => ((RegQueryInfoKey_Delegate)func)(hKey, lpClass, lpcClass,
                    lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen,
                    lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen,
                    lpcbSecurityDescriptor, lpftLastWriteTime),
                injection => injection.VirtualRegistry.GetKey(hKey).QueryInfo(
                    lpClass, lpcClass,
                    lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen,
                    lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen,
                    lpcbSecurityDescriptor, lpftLastWriteTime),
                "[REG KEY]: {0}.", hKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegQueryMultipleValues API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegQueryMultipleValues_Hooked(
            IntPtr hKey,
            IntPtr val_list,
            UInt32 num_vals,
            IntPtr lpValueBuf,
            /*ref UInt32*/ IntPtr ldwTotsize)
        {
            return HookSkeleton(
                func => ((RegQueryMultipleValues_Delegate)func)(
                    hKey, val_list, num_vals, lpValueBuf, ldwTotsize),
                injection => injection.VirtualRegistry.GetKey(hKey).QueryMultipleValues(
                        val_list, num_vals, lpValueBuf, ldwTotsize),
                "[REG KEY]: {0}.", hKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegQueryReflectionKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegQueryReflectionKey_Hooked(
            IntPtr hBase,
            /*ref Boolean*/ IntPtr bIsReflectionDisabled)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegQueryReflectionKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[BASE REG KEY]: {0}.", hBase);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegQueryReflectionKey(
                    hBase,
                    bIsReflectionDisabled);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegQueryValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegQueryValue_Hooked(
            IntPtr hKey,
            string lpSubKey,
            IntPtr lpData,
            IntPtr lpcbData)
        {
            return HookSkeleton(
                func => ((RegQueryValue_Delegate)func)(hKey, lpSubKey,
                    lpData, lpcbData),
                injection => injection.VirtualRegistry.GetKey(hKey).QueryValue(
                    lpSubKey, null, IntPtr.Zero, IntPtr.Zero, lpData, lpcbData),
                "[REG KEY]: {0}, [SUBKEY]: {1}.", hKey, lpSubKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegQueryValueEx API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegQueryValueEx_Hooked(
            IntPtr hKey,
            string lpValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            IntPtr lpcbData)
        {
//            if (lpValueName == "ShowSuperHidden")
//                Marshal.ReadInt32(IntPtr.Zero);
            return HookSkeleton(
                func => ((RegQueryValueEx_Delegate)func)(hKey, lpValueName, lpReserved, lpType,
                    lpData, lpcbData),
                injection => injection.VirtualRegistry.GetKey(hKey).QueryValue(
                    null, lpValueName, lpReserved, lpType, lpData, lpcbData),
                "[REG KEY]: {0}, [VALUE NAME]: {1}.", hKey, lpValueName);
        }

        /// <summary>
        /// The hook function that is called in response to RegReplaceKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegReplaceKey_Hooked(
            UIntPtr hKey,
            String lpSubKey,
            String lpNewFile,
            String lpOldFile)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegReplaceKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [SUBKEY]: {1}, [NEW FILE]: {2}, [OLD FILE]: {3}.", hKey, lpSubKey, lpNewFile, lpOldFile);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegReplaceKey(
                    /*(redirect) ? Helper.GetMirrorKey(injection, (int)hKey) : */hKey,
                    lpSubKey,
                    lpNewFile,
                    lpOldFile);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegRestoreKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegRestoreKey_Hooked(
            UIntPtr hKey,
            String lpFile,
            RegRestoreKeyFlags dwFlags)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegRestoreKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [FILE]: {1}.", hKey, lpFile);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegRestoreKey(
                    /*(redirect) ? Helper.GetMirrorKey(injection, (int)hKey) : */hKey,
                    lpFile,
                    dwFlags);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegSaveKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegSaveKey_Hooked(
            UIntPtr hKey,
            String lpFile,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegSaveKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [FILE]: {1}.", hKey, lpFile);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegSaveKey(
                    /*(redirect) ? Helper.GetMirrorKey(injection, (int)hKey) : */hKey,
                    lpFile,
                    lpSecurityAttributes);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegSaveKeyEx API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegSaveKeyEx_Hooked(
            UIntPtr hKey,
            String lpFile,
            /*ref SECURITY_ATTRIBUTES*/ IntPtr lpSecurityAttributes,
            RegSaveKeyExFlags Flags)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegSaveKeyExFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [FILE]: {1}.", hKey, lpFile);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegSaveKeyEx(
                    /*(redirect) ? Helper.GetMirrorKey(injection, (int)hKey) : */hKey,
                    lpFile,
                    lpSecurityAttributes,
                    Flags);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }

        /// <summary>
        /// The hook function that is called in response to RegSetKeyValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegSetKeyValue_Hooked(
            IntPtr hKey,
            String lpSubKey,
            String lpValueName,
            RegValueType dwType,
            IntPtr lpData,
            int cbData)
        {
            return HookSkeleton(
                func => ((RegSetKeyValue_Delegate)func)(hKey, lpSubKey, lpValueName, dwType, lpData,
                    cbData),
                injection => injection.VirtualRegistry.GetKey(hKey).SetValue(
                    lpSubKey, lpValueName, 0, dwType, lpData, cbData),
                "[REG KEY]: {0}, [SUBKEY]: {1}, [VALUE NAME]: {2}.", hKey, lpSubKey, lpValueName);
        }

        /// <summary>
        /// The hook function that is called in response to RegSetKeySecurity API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegSetKeySecurity_Hooked(
            UIntPtr hKey,
            SECURITY_INFORMATION SecurityInformation,
            /*ref IntPtr*/ IntPtr pSecurityDescriptor)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegSetKeySecurityFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}.", hKey);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                return (int)Win32Api.Error.ERROR_INVALID_HANDLE;
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;

        }

        /// <summary>
        /// The hook function that is called in response to RegSetValue API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegSetValue_Hooked(
            IntPtr hKey,
            String lpSubKey,
            RegValueType dwType,
            IntPtr lpData,
            Int32 cbData)
        {
            return HookSkeleton(
                func => ((RegSetValue_Delegate)func)(hKey, lpSubKey, dwType, lpData,
                    cbData),
                injection => injection.VirtualRegistry.GetKey(hKey).SetValue(
                    lpSubKey, null, 0, dwType, lpData, cbData),
                "[REG KEY]: {0}, [SUBKEY]: {1}.", hKey, lpSubKey);
        }

        /// <summary>
        /// The hook function that is called in response to RegSetValueEx API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegSetValueEx_Hooked(
            IntPtr hKey,
            String lpValueName,
            int Reserved,
            RegValueType dwType,
            IntPtr lpData,
            Int32 cbData)
        {
            return HookSkeleton(
                func => ((RegSetValueEx_Delegate)func)(hKey, lpValueName, Reserved, dwType, lpData,
                    cbData),
                injection => injection.VirtualRegistry.GetKey(hKey).SetValue(
                    null, lpValueName, Reserved, dwType, lpData, cbData),
                "[REG KEY]: {0}, [VALUE NAME]: {1}.", hKey, lpValueName);
        }

        /// <summary>
        /// The hook function that is called in response to RegLoadKey API function. 
        /// See MSDN for details.
        /// </summary>
        private static Int32 RegUnLoadKey_Hooked(
            UIntPtr hKey,
            String lpSubKey)
        {
            Injection injection = (Injection)HookRuntimeInfo.Callback;
            string thisFunc = RegUnLoadKeyFuncName;
            try
            {
                //Logs monitor entry.
                try
                {
                    RegLoggingForNotImplemented(injection, thisFunc, "[REG KEY]: {0}, [SUBKEY]: {1}.", hKey, lpSubKey);
                }
                catch (Exception ex)
                {
                    RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
                }

                // call original API...
                return RegUnLoadKey(
                    hKey,
                    lpSubKey);
            }
            catch (Exception ex)
            {
                RegLoggingForNotImplemented(injection, thisFunc, ex.Message);
            }

            return -1;
        }
    }
}
