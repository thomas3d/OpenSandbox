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
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Text;
using System.Runtime.InteropServices;
using EasyHook;
using System.Diagnostics;
using System.Threading;

namespace OpenSandbox
{
    // Class to be derived from if a class wants to implement IDisposable
    // and has no base class. This one simplifies IDisposable implementation
    public class DisposableBase : IDisposable
    {
        ~DisposableBase()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void DisposeManaged() { }
        // DisposeUnmanaged may be called from Finalize method
        // so managed member fields of this object may be already
        // null references, check for that
        protected virtual void DisposeUnmanaged() { }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // free the state of any contained objects
                DisposeManaged();
            }

            // free my own state
            DisposeUnmanaged();
        }
    }

    internal class CompositeDisposable : DisposableBase
    {
        private Stack<IDisposable> parts_ = new Stack<IDisposable>();

        internal void Attach(IDisposable part)
        {
            parts_.Push(part);
        }

        protected override void DisposeManaged()
        {
            foreach (IDisposable part in parts_)
            {
                try
                {
                    part.Dispose();
                }
                catch
                {
                    // TODO: when we switch to .NET 4, use AggregateException here
                    // meanwhile make a custom clone
                }
            }
        }
    }

    internal abstract class ThreadBase : DisposableBase
    {
        protected Thread thread_;

        protected void StartThread()
        {
            thread_ = new Thread(BaseThreadProc);
            thread_.IsBackground = true; // If Shutdown is not called, this thread won't prevent exiting of the app
            thread_.Start();
        }

        private void BaseThreadProc()
        {
            ThreadStarted();
            ThreadProc();
        }

        // Initialization in context of the thread
        protected virtual void ThreadStarted()
        {
            // TODO: IMPORTANT make sure this has effect on hooks which are already installed
            // otherwise make sure thread is crated before hooks are installed
            Hook.LeaveRegistryHooksOnlyForThread(Utils.GetCurrentThreadId());
        }

        protected abstract void ThreadProc();
    }

    /// <summary>
    /// The class implements helper methods for the library.
    /// </summary>
    internal class Utils
    {
        internal static int GetCurrentThreadId()
        {
            return AppDomain.GetCurrentThreadId();
        }

        internal static string GetInstallPath()
        {
            return Path.GetDirectoryName(Assembly.GetCallingAssembly().Location);
        }

        internal static string GetRootSearchDir()
        {
            return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        }

        internal static string GetExeDir()
        {
            string exeFileName = Process.GetCurrentProcess().MainModule.FileName;
            string exeDir = Path.GetDirectoryName(exeFileName);
            // For tests so that if injection fails, it writes in current dir
            string exeFileLwr = Path.GetFileName(exeFileName).ToLower();
            string exeDirLwr = Path.GetDirectoryName(exeFileName).ToLower();
            if (exeFileLwr == "qtagent32.exe") // For unit tests
                exeDir = Directory.GetCurrentDirectory();
            else if (exeFileLwr == "nethost.exe") // For unit tests
                exeDir = Path.GetDirectoryName(GetNetExeAssemblyPath());
            
            return Path.GetFullPath(exeDir);
        }

        internal static string GetNetExeAssemblyPath()
        {
            // This code is copied from RoozzNETSandboxingHost because it is not allowed to load OpenSandbox.dll
            string params_ = Environment.GetEnvironmentVariable("OSBOXPARAMS");
            int delimPos = params_.IndexOf(" ");
            return params_.Substring(delimPos + 2, params_.Length - delimPos - 3); // assumming path is quoted
        }

        private static string titleRootCached_ = null;


        //Ref: http://stackoverflow.com/questions/6344166/how-to-determine-which-version-of-windows
        internal static bool Is64BitProcess
        {
            get { return IntPtr.Size == 8; }
        }

        private enum CachedBool { FALSE, TRUE, NONE };
        private static CachedBool cachedIs64BitOperatingSystem_ = CachedBool.NONE;

        internal static bool Is64BitOperatingSystem
        {
            get
            {
                if (cachedIs64BitOperatingSystem_ != CachedBool.NONE)
                    return cachedIs64BitOperatingSystem_ != CachedBool.FALSE;
                bool is64Bit;
                // Clearly if this is a 64-bit process we must be on a 64-bit OS.
                if (Is64BitProcess)
                    is64Bit = true;
                else
                {
                    // Ok, so we are a 32-bit process, but is the OS 64-bit?
                    // If we are running under Wow64 than the OS is 64-bit.
                    bool isWow64;
                    is64Bit = ModuleContainsFunction("kernel32.dll", "IsWow64Process") &&
                        Win32Api.IsWow64Process(Win32Api.GetCurrentProcess(), out isWow64)
                        && isWow64;
                }
                // Using recursion to avoid copy-paste
                Is64BitOperatingSystem = is64Bit;
                return Is64BitOperatingSystem;
            }
            // For unit tests
            set
            {
                cachedIs64BitOperatingSystem_ = value ? CachedBool.TRUE : CachedBool.FALSE;
            }
        }

        static bool ModuleContainsFunction(string moduleName, string methodName)
        {
            IntPtr hModule = Win32Api.GetModuleHandle(moduleName);
            if (hModule != IntPtr.Zero)
                return Win32Api.GetProcAddress(hModule, methodName) != IntPtr.Zero;
            return false;
        }

        internal static void WakeUpThread(uint threadId)
        {
            if (threadId != 0)
            {
                IntPtr hThread = Win32Api.OpenThread(
                    Win32Api.ThreadAccessRights.THREAD_SUSPEND_RESUME,
                    false, threadId);
                if (hThread != IntPtr.Zero)
                {
                    Win32Api.ResumeThread(hThread);
                    Win32Api.CloseHandle(hThread);
                }
            }
        }
    }
}
