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
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace OpenSandbox
{
    internal class PInvokeHelper
    {
        private struct Signature
        {
            public FunctionIdentity Identity;
            public Type GeneralDelegate;

            public override int GetHashCode()
            {
                return Identity.GetHashCode() ^ GeneralDelegate.GetHashCode();
            }

            public override bool Equals(object obj)
            {
                return obj is Signature && this == (Signature)obj;
            }

            public static bool operator ==(Signature first, Signature second)
            {
                if (((object)first == null) || ((object)second == null))
                {
                    return ((object)first == null) == ((object)second == null);
                }
                return first.Identity == second.Identity && first.GeneralDelegate == second.GeneralDelegate;
            }

            public static bool operator !=(Signature first, Signature second)
            {
                return !(first == second);
            }
        }

        private static Dictionary<Signature, Delegate> boundToPInvoke_ = new Dictionary<Signature, Delegate>();

        internal static Delegate BindToPInvokeAnsi(FunctionIdentity identity, Type generalDelegate)
        {
            if (identity.IsUni)
            {
                identity = identity.ToAnsi();
            }
            return BindToPInvoke(CharSet.Ansi, identity, generalDelegate);
        }

        internal static Delegate BindToPInvokeUni(FunctionIdentity identity, Type generalDelegate)
        {
            return BindToPInvoke(CharSet.Unicode, identity, generalDelegate);
        }

        private static Delegate BindToPInvoke(
            CharSet charSet, FunctionIdentity identity, Type generalDelegate)
        {
            Signature signature = new Signature { Identity = identity, GeneralDelegate = generalDelegate };
            lock (boundToPInvoke_)
            {
                if (boundToPInvoke_.ContainsKey(signature)) return boundToPInvoke_[signature];
            }
            Delegate bound = Bind(identity, generalDelegate, charSet);
            lock (boundToPInvoke_)
            {
                boundToPInvoke_[signature] = bound;
            }
            return bound;
        }

        private static string BuildSuffix(CharSet charSet)
        {
            string suffix = charSet.ToString();
            return suffix.Replace(".", "_");
        }

        private static string BuildSuffix(FunctionIdentity identity, CharSet charSet)
        {
            string suffix = identity.Dll + "_" + identity.Function + "_" + charSet.ToString();
            return suffix.Replace(".", "_");
        }

        private static ModuleBuilder cachedModuleBuilder_ = null;

        private static Delegate Bind(FunctionIdentity identity, Type generalDelegate,
            CharSet charSet)
        {
            string suffix = BuildSuffix(identity, charSet);
            EnsureModuleBuilder();
            // Base class specified ONLY to make assembly reference OpenSandbox
            // before method gets defined so that types are resolved correctly
            TypeBuilder tb = cachedModuleBuilder_.DefineType(
                generalDelegate.Name + "PInvoke" + suffix,
                TypeAttributes.Class, typeof(Win32Api));

            MethodInfo method = generalDelegate.GetMethod("Invoke");
            ParameterInfo[] parameters = method.GetParameters();
            Type[] paramTypes = new Type[parameters.Length];
            for (int i = 0; i < paramTypes.Length; ++i)
            {
                paramTypes[i] = parameters[i].ParameterType;
            }


            MethodBuilder mb = tb.DefinePInvokeMethod(
                generalDelegate.Name + "PInvoke" + suffix, identity.Dll, identity.Function,
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl,
                CallingConventions.Standard,
                method.ReturnType, paramTypes,
                CallingConvention.StdCall,
                charSet);

            mb.SetImplementationFlags(
                mb.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);

            for (int i = 0; i < paramTypes.Length; i++)
            {
                var parameter = parameters[i];
                mb.DefineParameter(i + 1, ParameterAttributes.None, parameter.Name);
            }

            Type pinvokeType = tb.CreateType();

            return Delegate.CreateDelegate(
//                UnmanagedDelegate(generalDelegate, charSet),
                generalDelegate,
                pinvokeType.GetMethod(generalDelegate.Name + "PInvoke" + suffix));
        }

        private static Dictionary<Type, Type> cachedDecorators_ = new Dictionary<Type, Type>();

        internal static Delegate Ansi2UniDecorator(Delegate unicodeDelegate)
        {
            Type decoratorType = null;
            lock (cachedDecorators_)
            {
                if (cachedDecorators_.ContainsKey(unicodeDelegate.GetType()))
                {
                    decoratorType = cachedDecorators_[unicodeDelegate.GetType()];
                }
            }
            if (decoratorType == null)
            {
                decoratorType = UnmanagedDelegate(unicodeDelegate.GetType(), CharSet.Ansi);
                lock (cachedDecorators_)
                {
                    cachedDecorators_.Add(unicodeDelegate.GetType(), decoratorType);
                }
            }
            return Delegate.CreateDelegate(decoratorType, unicodeDelegate.Method);
        }

        private static void EnsureModuleBuilder()
        {
            lock (typeof(PInvokeHelper))
            {
                if (cachedModuleBuilder_ == null)
                {
                    AssemblyName aName = new AssemblyName("OpenSandboxDynamic");
                    AssemblyBuilder aBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(
                        aName, AssemblyBuilderAccess.Run);
                    cachedModuleBuilder_ = aBuilder.DefineDynamicModule(aName.Name);
                }
            }
        }

        private static Type UnmanagedDelegate(Type managedDelegate, CharSet charSet)
        {
            string suffix = BuildSuffix(charSet);
            EnsureModuleBuilder();
            TypeBuilder tb = cachedModuleBuilder_.DefineType(
                managedDelegate.Name + suffix,
                TypeAttributes.Public | TypeAttributes.Sealed,
                typeof(MulticastDelegate));

            Type[] ctorParams = new Type[] { typeof(CallingConvention) };
            ConstructorInfo ci = typeof(UnmanagedFunctionPointerAttribute).GetConstructor(ctorParams);
            FieldInfo fi = typeof(UnmanagedFunctionPointerAttribute).GetField("CharSet");
            CustomAttributeBuilder cab = new CustomAttributeBuilder(ci,
                new object[] { CallingConvention.StdCall },
                new FieldInfo[] { fi }, new object[] { CharSet.Ansi });
            tb.SetCustomAttribute(cab);
            ConstructorBuilder cb = tb.DefineConstructor(MethodAttributes.RTSpecialName |
                MethodAttributes.HideBySig | MethodAttributes.Public,
                CallingConventions.Standard, new Type[] { typeof(object), typeof(IntPtr) });
            cb.SetImplementationFlags(MethodImplAttributes.CodeTypeMask);

            MethodInfo unicodeMethod = managedDelegate.GetMethod("Invoke");
            ParameterInfo[] parameters = unicodeMethod.GetParameters();
            Type[] paramTypes = new Type[parameters.Length];
            for (int i = 0; i < paramTypes.Length; ++i)
            {
                paramTypes[i] = parameters[i].ParameterType;
            }


            MethodBuilder mb = tb.DefineMethod("Invoke",
                MethodAttributes.Public | MethodAttributes.HideBySig |
                MethodAttributes.Virtual, unicodeMethod.ReturnType, paramTypes);

            mb.SetImplementationFlags(MethodImplAttributes.CodeTypeMask);

            for (int i = 0; i < paramTypes.Length; i++)
            {
                var parameter = parameters[i];
                mb.DefineParameter(i + 1, ParameterAttributes.None, parameter.Name);
            }

            return tb.CreateType();
        }

        internal static void Copy(IntPtr src, IntPtr dst, int n)
        {
            byte[] temp = new byte[n];
            Marshal.Copy(src, temp, 0, n);
            Marshal.Copy(temp, 0, dst, n);
        }

        internal static void StringUniToAnsi(IntPtr strUni, IntPtr strAnsi, int nChars)
        {
            string str = Marshal.PtrToStringUni(strUni, nChars);
            CopyStringAnsi(str, strAnsi, nChars);
        }

        internal static void CopyStringAnsi(string str, IntPtr dst, int nChars)
        {
            using (HGlobalPtr pStr =
                new HGlobalPtr(Marshal.StringToHGlobalAnsi(str)))
            {
                Copy(pStr.Ptr, dst, nChars);
            }
        }

        internal static void CopyStringUni(string str, IntPtr dst, int nChars)
        {
            using (HGlobalPtr pStr =
                new HGlobalPtr(Marshal.StringToHGlobalUni(str)))
            {
                Copy(pStr.Ptr, dst, nChars * sizeof(char));
            }
        }
    }
}
