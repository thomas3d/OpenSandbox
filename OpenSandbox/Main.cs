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
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.IO;
using System.Windows.Forms;
using EasyHook;
using OpenSandbox.Logging;
using OpenSandbox.Registry;

namespace OpenSandbox
{
    /// <summary>Main.cs is a file containing definition of code injection entry point class <see cref="Injection"/>.</summary>

    /// <summary>Code injection entry point class</summary>
    /// <para>Instance of this class contains all the objects used by injected code,
    /// including all the hooks, virtual registry, helper exception handling and regular saving
    /// classes, etc.</para>
    /// <para>When <see cref="EasyHook.RemoteHooking.Inject"/> method is called (from
    /// <see cref="StartSandbox.EasyHookWrapper.Inject"/>) in a host process, the Injection class is
    /// instantiated through a call to constructor first (which is used only to setup IPC with host
    /// process. After that <see cref="Injection.Run"/> method is called.</para>
    /// <para>Injection.Run method does not return until the target process exits because when
    /// Injection.Run method exits, EasyHook uninstalls injected code.</para>
    public class Injection : EasyHook.IEntryPoint, IHookHolderAndCallback
    {
        internal static bool PROFILING_ENABLED = false;

        private Params params_;
        private CompositeDisposable shutdownManager_ = new CompositeDisposable();
        private SafeIPCInterface interface_;
        private VirtualRegistry registry_;
        private InstalledHooksNotOwningContainer installedHooks_ = new InstalledHooksNotOwningContainer();
        private ExceptionHandler exceptionHandler_;
        private FileAccessLogger fileAccessLogger_;
        private DateTime sandboxStartTime_ = DateTime.Now;
        private PathRebaser pathRebaser_;

        /// <summary>
        /// Sets up IPC between the code injected into target process and the host process.
        /// </summary>
        public Injection(
            RemoteHooking.IContext context, string channelName, string paramsXml)
        {
            interface_ = new SafeIPCInterface(channelName);
        }

        /// <summary>
        /// Injection class contains all the installed hooks, this function allows to find
        /// information about hook (name, etc) by its handle obtained, for example, from
        /// HookRuntimeInfo.
        /// </summary>
        /// <param name="handle">EasyHook.LocalHook handle of the hook</param>
        /// <returns>Detailed information about hook: name, delegate, etc.</returns>
        public Hook LookUp(LocalHook handle)
        {
            return installedHooks_.LookUp(handle);
        }

        /// <summary>
        /// Singleton (because we assume that code injection is done just once) virtual registry
        /// object containing registry sandboxing implementation.
        /// </summary>
        internal VirtualRegistry VirtualRegistry { get { return registry_; } }

        internal FileAccessLogger FileAccessLogger { get { return fileAccessLogger_; } }

        /// <summary>
        /// This event is called by .NET if target application exits (only for some apps,
        /// for others ExitProcess hook is called).
        /// </summary>
        private void CurrentDomain_ProcessExit(object sender, EventArgs e)
        {
            DebugLogger.WriteLine("ProcessExit");
            Shutdown();
        }

        /// <summary>
        /// This event is called by .NET if current domain is unloaded.
        /// </summary>
        private void CurrentDomain_DomainUnload(object sender, EventArgs e)
        {
            DebugLogger.WriteLine("DomainUnload");
            Shutdown();
        }

        /// <summary>
        /// This is a single sandboxing finalization method, which is called from ProcessExit event
        /// and from ExitProcess hook.
        /// </summary>
        /// <para>This method performs deinitialization in the needed order. It saves "diff" reghive
        /// if it was not yet saved. Uninstalls hooks, deinitializes helper objects: logger, saver
        /// thread.</para>
        private void Shutdown()
        {
            if (registry_ != null)
            {
                registry_ = null;
                //Debugger.Launch();
                DateTime dt = DateTime.Now;
                shutdownManager_.Dispose();
                // To make sure all hooks are uninstalled before shutdown is finished
                // TODO: wrap it into IDisposable installed during initialization
                NativeAPI.LhWaitForPendingRemovals();

                TimeSpan ts = DateTime.Now - dt;
                DebugLogger.WriteLine("Shutdown - took  {0}", ts);
            }

            DebugLogger.SafeDispose();
        }

        // This method is called when unhandled exception occured
        // most probably it is a crash in the target app,
        // because of some hooks. We have to be very careful here
        // to do really important denitinialization and avoid any exceptions.
        private void ShutdownOnException()
        {
            DebugLogger.SafeDispose();
        }

        /// <summary>
        /// Before the <see cref="StartSandbox.EasyHookWrapper.Inject"/> method is called (which calls
        /// <see cref="EasyHook.RemoteHooking.Inject"/> in turn), the target process is assummed to be
        /// just created in suspended mode. When the <see cref="Run"/> method finishes initialization
        /// of the injected code, it calls this method to resume the suspended process.
        /// </summary>
        /// <param name="threadId"></param>
        private void WakeUpProcess(uint threadId)
        {
            //This is required just when the library was injected with RemoteHooking.CreateAndInject(). This call resume the process.
            //If the library was injected into this process with RemoteHooking.Inject() then the below call does nothing.
            RemoteHooking.WakeUpProcess(); // useless when we use RemoteHooking.Inject().

            // Resumes process (its main thread) in all other cases.
            Utils.WakeUpThread(threadId);
        }

        /// <summary>
        /// Helper function creating virtual registry object using an encryption key
        /// if it is specified and installing string value alterer (rebasing paths).
        /// </summary>
        private VirtualRegistry CreateVirtualRegistry()
        {
            DebugLogger.WriteLine("Reg hive file: {0} for process {1}", params_.GetRegHivePath(), RemoteHooking.GetCurrentProcessId());

            Crypto.FileEncryptionLayer.AttachFile(params_.GetRegHivePath(), params_.GetCryptoKey());
            string diffHivePath = Path.GetFullPath("local.rh");
            Crypto.FileEncryptionLayer.AttachFile(diffHivePath, "");
            // This is because diff hive is saved first into a temporary file which is then atomically renamed
            Crypto.FileEncryptionLayer.AttachFile(diffHivePath + OffRegHive.TMP_SAVE_SUFFIX, "");

            VirtualRegistry result = new VirtualRegistry(params_.GetRegHivePath(), diffHivePath);
            result.DataAlterer.RegisterStringValueAlterer(pathRebaser_.RebasePath);
            return result;
        }

        private void AddHooks(InstalledHooks hooks)
        {
            shutdownManager_.Attach(hooks);
            installedHooks_.Add(hooks);
        }

        /// <summary>
        /// ExitProcess hook, which is used to catch the process exiting event and perform
        /// a graceful shutdown of sandboxing. It calls <see cref="Shutdown"/> method before
        /// calling native ExitProcess.
        /// </summary>
        private static void ExitProcess_Hooked(uint exitCode)
        {
            // Conciously using HookHelper<int> because
            // generics can't be specialized with void.
            new HookContext<int>(
                func =>
                {
                    string message = "Native call not supported for ExitProcess hook.";
                    Debug.Assert(false, message);
                    throw new Exception(message);
                },
                helper =>
                {
                    DebugLogger.WriteLine("ExitProcess");
                    ((Injection)helper.HookHolderAndCallback).Shutdown();
                    Win32Api.ExitProcess(exitCode);
                    return 0;
                },
                errorCode => 0, HookLogging.DefaultLogging,
                "[exitCode]: {0}.", exitCode).Call();
        }

        private void NowEmbeddedEvent()
        {
            fileAccessLogger_.NowEmbedded();
            TimeSpan startupTime = DateTime.Now - sandboxStartTime_;
            interface_.SafeReportPerformance(startupTime, HookContext<int>.RegistryCalls, params_.GetRedmineId());
        }

        

        /// <summary>
        /// Main injection method, which is called when injection is done and does not return
        /// until the target process exits.
        /// </summary>
        /// <para>Run method has the same signature as the constructor, the parameters' values
        /// are those which are passed to <see cref="StartSandbox.EasyHookWrapper.Inject"/> call.</para>
        /// <param name="context"></param>
        /// <param name="channelName">IPC channel name (used by constructor and not used by Run)</param>
        /// <param name="regHivePath">Path to the "base" reghive which is not changed (all changes are
        /// saved to a different "diff" reghive).</param>
        /// <param name="xml">XML containing file names and encryption keys associated with them
        /// (including reghive encryption key if used).</param>
        /// <param name="threadId">Thread ID of the main target process thread, used to resume it as soon
        /// as initialization is done.</param>
        public void Run(
            RemoteHooking.IContext context, string channelName, string paramsXml)
        {
            try
            {
                // Uncomment for debugging purpose
                // This is to preload assemblies and attach debugger to break into code simply
                // by a call to Debugger.Break
                // Debugger.Launch();

                // TODO: think about general way for components to initialize before hooks are installed.
                // static constructors do not work because they are called on first use.

                // To initialize crypto system, otherwise initialization may throw exceptions because
                // file hooks are already installed and initialization may be called from one of them.
                Aes.Create();

                params_ = new Params(paramsXml);

                if (!params_.IsProductionTitle())
                {
                    fileAccessLogger_ = new FileAccessLogger(params_.GetRedmineId());
                    shutdownManager_.Attach(fileAccessLogger_);
                }

                // Hotfix: Disabling crash report window for ACDSee
                exceptionHandler_ = new ExceptionHandler(ShutdownOnException, disabled: params_.GetRedmineId() == 1345);

                AppDomain.CurrentDomain.ProcessExit += new EventHandler(CurrentDomain_ProcessExit);
                AppDomain.CurrentDomain.DomainUnload += new EventHandler(CurrentDomain_DomainUnload);

                // Starting DebugLogger before file hooks are installed to make them disabled for its thread
                DebugLogger.WriteLine("---------------------startup----------------------");
                // TODO: put registration of SetUnhandledExceptionFilter hook to ExceptionHandler constructor
                // for this purpose may be make installedHooks a static variable so that anyone can register there
                AddHooks(new InstalledHooks(this, new Hooks(
                    new Delegate[] { new Win32Api.ExitProcess_Delegate(ExitProcess_Hooked),
                        new Win32Api.SetUnhandledExceptionFilter_Delegate(ExceptionHandler.SetUnhandledExceptionFilter_Hooked) })));

                shutdownManager_.Attach(exceptionHandler_);

                pathRebaser_ = new PathRebaser();

                AddHooks(new InstalledHooks(this, Logging.FileAccessFunctionsHookLib.Hooks));

                AddHooks(new InstalledHooks(this, Crypto.CryptoFunctionsHookLib.Hooks));

                registry_ = CreateVirtualRegistry();
                shutdownManager_.Attach(registry_);

                // TODO: TextPad in case of error during startup crashes after showing a error message
                // because .NET tries to access a HKEY returned by VirtualRegistry
                // after hooks are uninstalled in Shutdown method.
                // So either we shouldn't uninstall hooks at all, just save VirtualRegistry and that's it,
                // or do something else.
                AddHooks(new InstalledHooks(this, RegistryFunctionsHookLib.Hooks));

                // To debug hooks under XP 64, because breakpoints can be safely set for syscalls
                // only after hooks are installed
                //MessageBox.Show("Sandbox debug");

                shutdownManager_.Attach(new RegularHiveSaver(registry_));

                WakeUpProcess(params_.GetThreadId());
                interface_.SafelyReportInjectionDone();
            }
            catch (Exception ex)
            {
                interface_.SafelyReportInjectionError(ex);
                return;
            }

            // wait for host process termination...
            try
            {
                // TODO: think about disabling file hooks for this thread because they are called for pipe,
                // in the beginning of sandbox implementation this thread was disabled for all hooks
                // but this caused some problems... possibly with .NET interaction between threads
                // and passing registry handles, so do not disable all hooks, just file hooks
                // but make sure file access log is fine w/o reghives and may be some other files
                while (true)
                {
                    if (interface_.SafeCheckNowEmbedded())
                    {
                        NowEmbeddedEvent();
                    }
                    // Using Join instead of Sleep to pump message loop needed for the case of STA COM objects
                    // living in this thread
                    Thread.CurrentThread.Join(100);
                }
            }
            catch
            {
                // NET Remoting will raise an exception if host is unreachable
                // and if current process is exiting
            }
            DebugLogger.WriteLine("Exitting Run");
        }
    }
}
