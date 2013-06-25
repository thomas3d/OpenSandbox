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
using System.Text;
using System.Threading;

using EasyHook;
using OpenSandbox;
using OpenSandbox.Logging;
using OpenSandbox.Registry;

namespace OpenSandbox
{
    /// <summary>
    /// Attribute class for delegates defining signatures for hooks.
    /// It associates function name (name, dll) and category with the signature.
    /// </summary>
    [AttributeUsage(AttributeTargets.Delegate, Inherited = false)]
    internal class DllFunctionAttribute : Attribute
    {
        private FunctionIdentity identity_;
        private string category_;

        internal DllFunctionAttribute(string dll, string function, string category)
        {
            identity_ = new FunctionIdentity(dll, function);
            category_ = category;
        }

        internal FunctionIdentity Identity { get { return identity_; } }
        internal string Category { get { return category_; } }
    }

    /// <summary>
    /// DLL exported function identity: name and name of dll.
    /// </summary>
    [Serializable]
    internal class FunctionIdentity
    {
        private string dll_;
        private string function_;

        internal string Dll { get { return dll_; } }
        internal string Function { get { return function_; } }

        internal FunctionIdentity(string dll, string function)
        {
            dll_ = dll;
            function_ = function;
        }

        /// <summary>
        /// Whether the function is Ansi (all Windows API functions working with strings
        /// in Ansi format have names ending with 'A'.
        /// </summary>
        internal bool IsAnsi { get { return function_.EndsWith("A"); } }
        /// <summary>
        /// Whether the function is Unicode.
        /// </summary>
        internal bool IsUni { get { return function_.EndsWith("W"); } }

        /// <summary>
        /// Get the name of the Ansi version of the function.
        /// </summary>
        internal FunctionIdentity ToAnsi()
        {
            if (!IsUni) throw new ArgumentException(
                "Function should be Unicode and end with W to be converted to Ansi.");
            return new FunctionIdentity(dll_,
                function_.Substring(0, function_.Length - 1) + "A");
        }

        public override int GetHashCode()
        {
            return dll_.GetHashCode() ^ function_.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            return obj is FunctionIdentity && this == (FunctionIdentity)obj;
        }

        public static bool operator ==(FunctionIdentity first, FunctionIdentity second)
        {
            if (((object)first == null) || ((object)second == null))
            {
                return ((object)first == null) == ((object)second == null);
            }
            return first.dll_ == second.dll_ && first.function_ == second.function_;
        }

        public static bool operator !=(FunctionIdentity first, FunctionIdentity second)
        {
            return !(first == second);
        }
    }

    public interface IHookHolderAndCallback
    {
        Hook LookUp(LocalHook handle);
    }

    /// <summary>
    /// Class describing hook: function identity (name, dll), signature,
    /// hook handler delegate and hook category (registry/files/etc).
    /// </summary>
    /// <para>Creating instance of this class does not install hook, it just
    /// contains information about it <see cref="InstalledHooks"/>.</para>
    [Serializable]
    public class Hook
    {
        private FunctionIdentity identity_;
        // Statically defined delegate type to perform
        // params type checking
        private Type signature_;
        // Signature bound to hook impl, and either ansi or unicode.
        // For Ansi hooks its delegate type is dynamically defined.
        private Delegate hookHandler_;
        private string hookCategory_;
        private static List<int> threadsWithRegistryHooksOnly_ = new List<int>();

        internal FunctionIdentity Identity { get { return identity_; } }
        internal Type Signature { get { return signature_; } }
        internal Delegate HookHandler { get { return hookHandler_; } }
        internal string HookCategory { get { return hookCategory_; } }

        static Hook()
        {
            LocalHook.GlobalThreadACL.SetExclusiveACL(new int[] { });
        }

        /// <summary>
        /// Constructor in addition to just filling the fields with the parameters' values,
        /// initializes cache of bound delegates.
        /// </summary>
        /// <para>For both Ansi and Unicode versions of the same function, the same signature
        /// delegate is used, but to perform actual call, it is bound using
        /// <see cref="PInvokeHelper.BindToPInvokeAnsi"/>
        /// and <see cref="PInvokeHelper.BindToPInvokeUnicode"/>.</para>
        internal Hook(FunctionIdentity identity,
            Type signature,
            Delegate hookHandler,
            string hookCategory)
        {
            signature_ = signature;
            identity_ = identity;
            hookHandler_ = hookHandler;
            hookCategory_ = hookCategory;
            // Building cache of bound pinvoke delegates ahead of itme to avoid nested calls
            // which fail: (reg*hook -> Bind -> reg* by .NET -> Bind)
            PInvokeHelper.BindToPInvokeAnsi(identity, signature);
            PInvokeHelper.BindToPInvokeUni(identity, signature);
        }

        public static void LeaveRegistryHooksOnlyForThread(int threadId)
        {
            threadsWithRegistryHooksOnly_.Add(threadId);
        }

        /// <summary>Returns delegate with the signature of the hook bound
        /// to the function name of the hook in associated dll.</summary>
        internal Delegate BindToPInvoke(bool ansi)
        {
            if (ansi)
            {
                return PInvokeHelper.BindToPInvokeAnsi(identity_, signature_);
            }
            return PInvokeHelper.BindToPInvokeUni(identity_, signature_);
        }
        
        /// <summary>Installs hook and associates it with the specified injection object
        /// returns object which needs to be kept alive to keep hook installed.</summary>
        internal LocalHook Install(IHookHolderAndCallback hhac)
        {
            LocalHook result = LocalHook.Create(LocalHook.GetProcAddress(identity_.Dll, identity_.Function),
                hookHandler_, hhac);
            // Don't forget that all hooks will start deactivated...
            // The following ensures that all threads are intercepted:
            // by default we exclude _no_ threads (empty array).
            int[] ACL = new int[] { };
            if (hookCategory_ != Win32Api.CATEGORY_REGISTRY)
            {
                ACL = threadsWithRegistryHooksOnly_.ToArray();
            }
            result.ThreadACL.SetExclusiveACL(ACL);
            return result;
        }
    }

    /// <summary>
    /// HookBarrier is a class used by "layers"(categories) of hooks, for instance, "registry"
    /// layer, "files" layer, etc to ensure that in the extent of the call stack of a particular
    /// thread, there is no more than one call of each layer.
    /// </summary>
    /// <para>This is to make hook of RegCreateKey calling RegOpenKey, for instance,
    /// call native version of RegOpenKey and not get into the RegOpenKey hook
    /// (to prevent kind of recursive hook layer execution).</para>
    /// <para>Even if there is already hook of this layer down the call stack,
    /// in this case <see cref="Injected"/> == false,
    /// the hook is called, but it is supposed to call native version
    /// of the function and do no other job.</para>
    internal class HookBarrier : DisposableBase
    {
        [ThreadStatic]
        static private Dictionary<string, Hook> injectedByCat_;
        [ThreadStatic]
        static private Stack<Hook> injectedStack_;
        private bool injected_ = false;
        private Hook currentFunc_ = null;

        /// <summary>
        /// Indicates whether hook is the first of the layer (category) in the call stack.
        /// </summary>
        /// <para>True means that hook may do its job, false means it should just call native
        /// function and return.</para>
        internal bool Injected { get { return injected_; } }

        /// <summary>
        /// Tells whether the topmost called hook in the current thread call stack
        /// is Ansi function.
        /// </summary>
        /// <para>It is used in Ansi<->Unicode conversion classes to identify whether
        /// conversion has to be done or not.</para>
        // TODO: replace with IsInjectedFuncAnsi
        internal static bool IsLastInjectedFuncAnsi
        {
            get
            {
                return injectedStack_ != null && injectedStack_.Count > 0 &&
                    injectedStack_.Peek().Identity.IsAnsi;
            }
        }

        /// <summary>
        /// Tells whether the topmost called hook of the current category (layer)
        /// is Ansi function. Helps to identify which native function to call.
        /// </summary>
        internal bool IsInjectedFuncAnsi
        {
            get
            {
                return injectedByCat_.ContainsKey(currentFunc_.HookCategory) &&
                    injectedByCat_[currentFunc_.HookCategory].Identity.IsAnsi;
            }
        }
        internal Hook CurrentFunc { get { return currentFunc_; } }

        /// <summary>
        /// Installs hook barrier within the hook body
        /// </summary>
        /// <para>Saves entire stack of called hooks, maintains it,
        /// also keeps track of called hooks by category.</para>
        /// <param name="func">Hook info object obtained from <see cref="Injection.LookUpHook"/>.</param>
        internal HookBarrier(Hook func)
        {
            if (func == null)
            {
                throw new ArgumentNullException("Function passed to hook barrier should not be null.");
            }
            currentFunc_ = func;
            if (injectedByCat_ == null) injectedByCat_ = new Dictionary<string, Hook>();
            if (injectedStack_ == null) injectedStack_ = new Stack<Hook>();
            injected_ = !injectedByCat_.ContainsKey(func.HookCategory);
            if (injected_)
            {
                injectedByCat_.Add(func.HookCategory, func);
                injectedStack_.Push(func);
            }
        }

        /// <summary>
        /// Uninstalls hook barrier.
        /// </summary>
        protected override void DisposeUnmanaged()
        {
            // free my own state
            if (injected_)
            {
                if (injectedStack_ != null) injectedStack_.Pop();
                if (injectedByCat_ != null) injectedByCat_.Remove(currentFunc_.HookCategory);
                injected_ = false;
            }
        }
    }

    /// <summary>
    /// Hooks container, allows to add new hooks by specifying signature delegates
    /// marked with DllFunctionAttribute attribute.
    /// </summary>
    public class Hooks
    {
        private Dictionary<FunctionIdentity, Hook> dict_ =
            new Dictionary<FunctionIdentity, Hook>();
        internal Dictionary<FunctionIdentity, Hook>.ValueCollection List
        { get { return dict_.Values; } }

        /// <summary>
        /// Initializes container with of hooks based on the array of signature delegates.
        /// </summary>
        /// <param name="hooks">Each of the delegates should
        /// have DllFunctionAttribute specifying function name and dll name
        /// and should be bound to appropriate hook handler.</param>
        internal Hooks(Delegate[] hooks=null)
        {
            if (hooks == null) return;
            foreach (Delegate h in hooks)
            {
                Add(h);
            }
        }

        /// <summary>
        /// Adds hook identified by delegate specifying signature and hook handler method,
        /// DllFunctionAttribute, associated with delegate specifying function name and dll
        /// name to the container.
        /// </summary>
        /// <para>If function also has an Ansi version, it is also added to the container.</para>
        internal void Add(Delegate hook)
        {
            FunctionIdentity identity;
            string category;
            GetHookAttribs(hook.GetType(), out identity, out category);

            // TODO: decouple the hooks container and the strategy
            // how hooks are added into container

            if (identity.Dll == Win32Api.Advapi32DllName)
            {
                // Registry functions in windows 7 also reside in kernel32.dll, some of system
                // dlls like oleaut32.dll call kernel32.dll versions
                FunctionIdentity kernel32Identity = new FunctionIdentity(Win32Api.Kernel32DllName, identity.Function);
                Add(kernel32Identity, hook, category);
                // Registry functions in windows 8 also reside in kernelbase.dll, some of system
                // dlls like combase.dll call kernelbase.dll versions
                FunctionIdentity kernelBaseIdentity = new FunctionIdentity(Win32Api.KernelBaseDllName, identity.Function);
                Add(kernelBaseIdentity, hook, category);
            }
            Add(identity, hook, category);
        }

        private void Add(FunctionIdentity identity, Delegate hook, string category)
        {
            // The following call checks if function is already in the dict
            dict_.Add(identity, new Hook(identity, hook.GetType(), hook, category));
            if (identity.IsUni)
            {
                // For functions accepting string params we add Ansi version too
                FunctionIdentity ansiId = identity.ToAnsi();
                if (!dict_.ContainsKey(ansiId))
                {
                    dict_.Add(ansiId, new Hook(ansiId, hook.GetType(),
                        PInvokeHelper.Ansi2UniDecorator(hook), category));
                }
            }
        }

        /// <summary>
        /// Basing on signature delegate having DllFunctionAttribute, determines function name,
        /// dll name and hook category (registry/files/...).
        /// </summary>
        private void GetHookAttribs(Type signature, out FunctionIdentity identity, out string category)
        {
            DllFunctionAttribute[] attrs = (DllFunctionAttribute[])signature.GetCustomAttributes(
                typeof(DllFunctionAttribute), false);
            if (attrs.Length != 1)
            {
                throw new ArgumentException("Hook delegate should have single DllFunction attributes");
            }
            identity = attrs[0].Identity;
            category = attrs[0].Category;
        }
    }

    /// <summary>
    /// RAII-based container of installed hooks. Install hooks in the constructor.
    /// Uninstalls them in Dispose method.
    /// </summary>
    public class InstalledHooks : DisposableBase
    {
        private Dictionary<LocalHook, Hook> dict_ = new Dictionary<LocalHook, Hook>();

        /// <summary>
        /// Install hooks associated with the injection object. This means that injection object
        /// will be passed as the <see cref="HookRuntimeInfo.Callback"/> into each hook call.
        /// </summary>
        public InstalledHooks(IHookHolderAndCallback hookHolderAndCallback, Hooks funcs)
        {
            foreach (Hook hf in funcs.List)
            {
                // We must save refence to LocalHook object otherwise garbage collector destroys the object.
                try
                {
                    dict_.Add(hf.Install(hookHolderAndCallback), hf);
                }
                // We ignore errors if hook installation failed - assuming this function
                // does not exist on the current OS
                catch (MissingMethodException)
                { }
                // Same thing about dlls which do not exist under some OSes like kernelbase.dll
                catch (DllNotFoundException)
                { }
            }
        }

        /// <summary>
        /// Lookup hook description by hook handle returned by <see cref="HookRuntimeInfo.Handle"/>.
        /// </summary>
        public Hook LookUp(LocalHook handle)
        {
            if (!dict_.ContainsKey(handle)) return null;
            return dict_[handle];
        }

        /// <summary>
        /// Uninstalls hooks.
        /// </summary>
        protected override void DisposeManaged()
        {
            foreach (LocalHook lh in dict_.Keys)
            {
                lh.Dispose();
            }
            dict_.Clear();
        }
    }

    /// <summary>
    /// Composite pattern for InstalledHooks, allows lookup
    /// of the hook by handle in all the hooks. But does not take care of
    /// their lifetime.
    /// </summary>
    internal class InstalledHooksNotOwningContainer
    {
        private List<InstalledHooks> list_ = new List<InstalledHooks>();

        internal void Add(InstalledHooks hooks)
        {
            list_.Add(hooks);
        }

        internal Hook LookUp(LocalHook handle)
        {
            foreach (InstalledHooks hooks in list_)
            {
                if (hooks != null)
                {
                    Hook result = hooks.LookUp(handle);
                    if (result != null) return result;
                }
            }
            return null;
        }
    }

    internal delegate ReturnType HookClosure<ReturnType>(Delegate func);
    internal delegate ReturnType HookOperation<ReturnType>(HookContext<ReturnType> helper);
    internal delegate void VoidOperation(Injection injection);
    internal delegate ReturnType ErrorHandler<ReturnType>(int errorCode);
    internal delegate void LoggingCallback(IHookHolderAndCallback hhac, FunctionIdentity identity,
            string format, params object[] args);

    internal class HookContext<ReturnType>
    {
        private HookClosure<ReturnType> closure_;
        private HookOperation<ReturnType> operation_;
        private ErrorHandler<ReturnType> errorHandler_;
        private LoggingCallback logging_;
        private string format_;
        private object[] args_;
        private IHookHolderAndCallback hhac_;
        private HookBarrier hb_;

        //private static bool loggingOnly_ = true;
        private const bool LOGGING_ONLY = false;
        private const bool LOGGING_ALWAYS = false;
        //private static bool loggingAlways_ = true;
        private const bool LOG_BEGIN = false;

        internal IHookHolderAndCallback HookHolderAndCallback { get { return hhac_; } }

        internal HookContext(HookClosure<ReturnType> closure,
            HookOperation<ReturnType> operation, ErrorHandler<ReturnType> errorHandler,
            LoggingCallback logging, string format, params object[] args)
        {
            closure_ = closure;
            operation_ = operation;
            errorHandler_ = errorHandler;
            logging_ = logging;
            format_ = format;
            args_ = args;
        }

        private void Logging(string format, string prefix="")
        {
            logging_(hhac_,
                new FunctionIdentity(hb_.CurrentFunc.Identity.Dll,
                    prefix + hb_.CurrentFunc.Identity.Function),
                format, args_);
        }

        internal ReturnType CallNative(bool forceLogging = false)
        {
            if (hb_ == null)
            {
                throw new SystemException("Trying to call native function when HookBarrier is not installed.");
            }
            ReturnType result = closure_(
                hb_.CurrentFunc.BindToPInvoke(hb_.IsInjectedFuncAnsi));
            if (LOGGING_ALWAYS || (hb_.Injected && LOGGING_ONLY) ||
                forceLogging)
            {
                Logging(String.Format("{0} Result: {1} LastError: {2}",
                    format_, result, Win32Api.GetLastError()), prefix: "Native ");
            }
            return result;
        }

        private static int registryCalls_ = 0;

        public static int RegistryCalls { get { return registryCalls_; } }

        internal ReturnType Call()
        {
            try
            {
                hhac_ = (IHookHolderAndCallback)HookRuntimeInfo.Callback;

                using (hb_ = new HookBarrier(
                    hhac_.LookUp(HookRuntimeInfo.Handle)))
                {
                    try
                    {
                        if (!hb_.Injected || LOGGING_ONLY)
                        {
                            return CallNative();
                        }

                        if (LOG_BEGIN)
                            Logging("Begin");
                        if (hb_.CurrentFunc.HookCategory == Win32Api.CATEGORY_REGISTRY)
                            registryCalls_++;
                        ReturnType result = operation_(this);
                        uint errorCode = Win32Api.GetLastError();
                        Logging(String.Format("{0} Result: {1} LastError: {2}", format_, result, errorCode));
                        Win32Api.SetLastError(errorCode);
                        return result;
                    }
                    catch (Win32Exception re)
                    {
                        Logging(format_ + " RegistryException: " + re.ErrorCode.ToString());
                        return errorHandler_(re.ErrorCode);
                    }
                    catch (Exception ex)
                    {
                        Logging(format_ + " Exception: " + ex.ToString());
                        return errorHandler_((int)Win32Api.Error.ERROR_ACCESS_DENIED);
                    }
                }
            }
            catch
            {
                return errorHandler_((int)Win32Api.Error.ERROR_ACCESS_DENIED);
            }
        }
    }

    internal class HookLogging
    {
        // This function is exception-safe and does not throw any exceptions
        internal static void DefaultLogging(IHookHolderAndCallback hhac, FunctionIdentity identity,
            string format, params object[] args)
        {
            try
            {
                DebugLogger.WriteLine(Thread.CurrentThread.ManagedThreadId.ToString("D2") + " " +
                    identity.Function + " " + format, args);
            }
            catch (Exception) { }
        }

        internal static void NoLogging(IHookHolderAndCallback hhac, FunctionIdentity identity,
            string format, params object[] args)
        {
        }
    }
}
