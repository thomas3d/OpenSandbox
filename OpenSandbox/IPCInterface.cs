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
using System.Threading;
using EasyHook;
using OpenSandbox.Logging;

namespace OpenSandbox
{
    /// <summary>IPC class for interaction between injection host process
    /// and the target process.</summary>
    /// <para>All methods of this class are executed in the host process,
    /// but some are called from the target process and the calls are marshalled
    /// to the host process.</para>
    /// <para>For now the class is used only to notify about results of injection
    /// initialization, when it is finished and if there was an exception.</para>
    /// <para> The following is comment from EasyHook:
    /// This is the class where our clients will connect to!
    /// 
    /// Please note that setting any breakpoint here will cause the related
    /// thread in the client process to block until you continue execution!
    /// So don't wonder if your browser (for example) hangs when you set a 
    /// breakpoint ;-)... Let's say you can debug a part of the code the client
    /// is executing (that's not technically correct)
    /// 
    /// In Windows 2000 debugging the following seems to cause problems.</para>
    public class IPCInterface : MarshalByRefObject
    {
        private struct InjectionResult
        {
            public bool Success { get { return Error == null; } }
            public Exception Error;
        }
        private static Dictionary<int, InjectionResult> resultsByPID_
            = new Dictionary<int,InjectionResult>();
        private static EventWaitHandle resultAdded_
            = new AutoResetEvent(false);

        /// <summary>
        /// The method is called in the host process to wait until the injection is done and initialization
        /// of the injected code is complete.
        /// </summary>
        public static void WaitForInjection(int clientPID)
        {
            do
            {
                lock (resultsByPID_)
                {
                    if (resultsByPID_.ContainsKey(clientPID))
                    {
                        InjectionResult result = resultsByPID_[clientPID];
                        resultsByPID_.Remove(clientPID);

                        if (!result.Success)
                            throw result.Error;
                        return;
                    }
                }
            } while (resultAdded_.WaitOne());
        }

        private enum EmbeddedState { NotEmbedded, Embedded, Handled };
        private static EmbeddedState embeddedState_ = EmbeddedState.NotEmbedded;

        /// <summary>
        /// The method is called in the host process to tell the Sandbox that the Window has embedded. 
        /// </summary>
        public static void NowEmbedded()
        {
            embeddedState_ = EmbeddedState.Embedded;
        }

        public bool CheckNowEmbedded()
        {
            if (embeddedState_ != EmbeddedState.Embedded) return false;
            embeddedState_ = EmbeddedState.Handled;
            return true;
        }

        /// <summary>
        /// The method is called from the target process'side to notify exception that
        /// was thrown during initialization of the injected code.
        /// </summary>
        /// <param name="clientPID">Process ID of the target app where the exception happened.</param>
        /// <param name="error">Exception being thrown.</param>
        public void ReportInjectionError(
            int clientPID,
            Exception error)
        {
            lock (resultsByPID_)
            {
                resultsByPID_.Add(clientPID, new InjectionResult { Error = error });
                resultAdded_.Set();
            }
        }

        /// <summary>
        /// The method is called from the target process'side to notify that
        /// injected code was initialized successfully.
        /// </summary>
        /// <param name="clientPID">Process ID of the target app where injected code initialization
        /// is done.</param>
        public void ReportInjectionDone(int clientPID)
        {
            lock (resultsByPID_)
            {
                resultsByPID_.Add(clientPID, new InjectionResult { Error = null });
                resultAdded_.Set();
            }
        }

        public delegate void PerformanceHandlerDelegate(TimeSpan startupTime, int regCalls, uint redmineId);

        private static PerformanceHandlerDelegate performanceHandler_;

        public static PerformanceHandlerDelegate PerformanceHandler { set { performanceHandler_ = value; } }

        public void ReportPerformance(TimeSpan startupTime, int regCalls, uint redmineId)
        {
            // Do the error reporting from here, it is executed within host (broker) process
            if (performanceHandler_ != null)
                performanceHandler_(startupTime, regCalls, redmineId);
        }
    }

    /// <summary>
    /// Helper class wrapping around <see cref="IPCInterface"/> to provide exception-safe interface.
    /// All its methods are executed in the context of the current (target) process.
    /// </summary>
    internal class SafeIPCInterface
    {
        IPCInterface interface_;

        public SafeIPCInterface(string channelName)
        {
            interface_ = RemoteHooking.IpcConnectClient<IPCInterface>(channelName);
        }

        public void SafelyReportInjectionDone()
        {
            try
            {
                interface_.ReportInjectionDone(RemoteHooking.GetCurrentProcessId());
            }
            catch { }
            DebugLogger.WriteLine("Injection successfully done");
        }

        public void SafelyReportInjectionError(Exception ex)
        {
            DebugLogger.WriteLine("Injection error: {0}", ex.ToString());
            try
            {
                interface_.ReportInjectionError(RemoteHooking.GetCurrentProcessId(), ex);
                DebugLogger.WriteLine("Injection error reported for {0}", RemoteHooking.GetCurrentProcessId());
            }
            catch (Exception e)
            {
                DebugLogger.WriteLine("Injection reporting error {0}", e.ToString());
                try
                {
                    interface_.ReportInjectionError(RemoteHooking.GetCurrentProcessId(), e);
                }
                catch { }
            }
        }

        public bool SafeCheckNowEmbedded()
        {
            try
            {
                return interface_.CheckNowEmbedded();
            }
            catch
            {
            }
            return false;
        }

        public void SafeReportPerformance(TimeSpan startupTime, int regCalls, uint redmineId)
        {
            try
            {
                interface_.ReportPerformance(startupTime, regCalls, redmineId);
            }
            catch { }
        }
    }
}
