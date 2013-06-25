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
using System.Diagnostics;
using System.Runtime.InteropServices;
using OpenSandbox.Logging;

namespace OpenSandbox
{
    /// <summary>
    /// Helper class, handling SEH (Structured Exceptions) which were not handled
    /// by target application which usually means crashes. And calling handler
    /// from CrashReport.dll which shows "Bug Report Submit" form to user.
    /// </summary>
    /// <para>The exception handler is installed by calling its constructor AND by installing
    /// SetUnhandledExceptionFilter_Hooked hook. The uninstallation is done by calling Dispose
    /// method.</para>
    // TODO: make it singleton because it uses static members or avoid static members
    internal class ExceptionHandler : DisposableBase
    {
        private static Win32Api.UnhandledExceptionFilter_Delegate filter_ =
            new Win32Api.UnhandledExceptionFilter_Delegate(ExceptionHandler.UnhandledExceptionFilter);
        private Win32Api.UnhandledExceptionFilter_Delegate oldFilter_;

        public delegate void ShutdownOnException();
        private static ShutdownOnException shutdown_;

        internal ExceptionHandler(ShutdownOnException shutdown, bool disabled = false)
        {
            shutdown_ = shutdown;
            if (disabled)
            {
                filter_ = new Win32Api.UnhandledExceptionFilter_Delegate(ExceptionHandler.EmptyUnhandledExceptionFilter);
            }
            oldFilter_ = Win32Api.SetUnhandledExceptionFilter(filter_);
        }

        protected override void DisposeUnmanaged()
        {
            // Some crash (ACDSee Pro redmine id 1345) may happen even after here, so leaving
            // our exception filter until the process terminates (commented next line)
            // Win32Api.SetUnhandledExceptionFilter(oldFilter_);
        }

        internal static Win32Api.UnhandledExceptionFilter_Delegate SetUnhandledExceptionFilter_Hooked(
            Win32Api.UnhandledExceptionFilter_Delegate lpTopLevelExceptionFilter)
        {
            return new HookContext<Win32Api.UnhandledExceptionFilter_Delegate>(
                func =>
                {
                    string message = "Native call is not supported for SetUnhandledExceptionFilter.";
                    Debug.Assert(false, message);
                    throw new Exception(message);
                },
                helper =>
                {
                    // Ignoring the value set by user and always installing our handler
                    Win32Api.SetUnhandledExceptionFilter(filter_);
                    // We could return any value, because we don't give control
                    // to application's unhandled exception filter so it won't call it.
                    return filter_;
                },
                errorCode => filter_,
                HookLogging.DefaultLogging,
                "[lpFilter]: {0}.", (long)Marshal.GetFunctionPointerForDelegate(lpTopLevelExceptionFilter)).Call();
        }

        /// <summary>
        /// Unhandled exception handler showing "bug report" form and asking user to send it.
        /// </summary>
        [DllImport("CrashReporter.dll", EntryPoint = "_CustomUnhandledExceptionFilter@4")]
        private static extern int CustomUnhandledExceptionFilter(IntPtr ExceptionInfo);

        /// <summary>
        /// Unhandled exception handler, called within .NET context. As it may be called due to crash
        /// in one of the hooks, the <see cref="HookBarrier"/> will prevent that (crashed)
        /// hook from working correctly, so we create a separate thread to work around that and
        /// call crash reporter from that separate thread, we use native threads because
        /// .NET threads may also access that crashed hook.
        /// </summary>
        private static int EmptyUnhandledExceptionFilter(IntPtr ExceptionInfo)
        {
            return (int)Win32Api.EXCEPTION_RESULT.EXCEPTION_EXECUTE_HANDLER;
        }

        private static int UnhandledExceptionFilter(IntPtr ExceptionInfo)
        {
            // Using separate thread to avoid disabling hook which leads to crash
            DebugLogger.WriteLine("Entered ExceptionHandler.UnhandledExceptionFilter");
            threadResult_ = (int)Win32Api.EXCEPTION_RESULT.EXCEPTION_CONTINUE_SEARCH;
            try
            {
                uint threadId;
                IntPtr hThread = Win32Api.CreateThread(IntPtr.Zero, 0, UnhandledExceptionFilterThread, ExceptionInfo, 0, out threadId);
                if (hThread != IntPtr.Zero)
                {
                    Win32Api.WaitForSingleObject(hThread, Win32Api.INFINITE);
                    Win32Api.CloseHandle(hThread);
                }
            }
            catch (Exception e)
            {
                DebugLogger.WriteLine("ExceptionHandler.UnhandledExceptionFilter exception " + e.ToString());
            }
            try
            {
                shutdown_(); // Loggers are down past this line
            }
            catch { }
            return threadResult_;
        }

        private static int threadResult_;

        /// <summary>
        /// Thread function just calling the exception handler from the CrashReporter.dll
        /// in the context of separate thread.
        /// </summary>
        private static void UnhandledExceptionFilterThread(IntPtr param)
        {
            try
            {
                DebugLogger.WriteLine("Entered ExceptionHandler.UnhandledExceptionFilterThread");
                IntPtr ExceptionInfo = param;
                threadResult_ = CustomUnhandledExceptionFilter(ExceptionInfo);
            }
            catch (Exception e)
            {
                DebugLogger.WriteLine("ExceptionHandler.UnhandledExceptionFilterThread exception " + e.ToString());
            }
        }
    }
}
