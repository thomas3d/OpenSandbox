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

namespace OpenSandbox.Registry
{
    internal static class GetKeySecurityExtension
    {
        internal static void GetKeySecurity(
            this VirtualKey key,
            Win32Api.SECURITY_INFORMATION SecurityInformation,
            IntPtr pSecurityDescriptor,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor)
        {
            key.ApplyReadOperation(null,
                new KeySecurity(Win32Api.KeySecurity.MAXIMUM_ALLOWED),
                keyImpl => keyImpl.TryApply(new GetKeySecurity(SecurityInformation,
                    pSecurityDescriptor, lpcbSecurityDescriptor)));
        }
    }

    internal class GetKeySecurity : IKeyImplHandler
    {
        private Win32Api.SECURITY_INFORMATION securityInformation_;
        private IntPtr pSecurityDescriptor_;
        private IntPtr lpcbSecurityDescriptor_;

        internal GetKeySecurity(
            Win32Api.SECURITY_INFORMATION SecurityInformation,
            IntPtr pSecurityDescriptor,
            /*ref UInt32*/ IntPtr lpcbSecurityDescriptor)
        {
            securityInformation_ = SecurityInformation;
            pSecurityDescriptor_ = pSecurityDescriptor;
            lpcbSecurityDescriptor_ = lpcbSecurityDescriptor;
        }

        public bool Handle(WindowsKey key)
        {
            return Win32Exception.CheckIfFoundAndNoError(
                Win32Api.RegGetKeySecurity(key.Handle, securityInformation_, pSecurityDescriptor_, lpcbSecurityDescriptor_));
        }

        public bool Handle(OffRegKey key)
        {
            // TODO: Until we have implemented SetKeySecurity and made sure that original
            // sandboxie-generated reghives contain correct security descriptors, we support this only
            // for windows registry.
            return false;
//            RegistryException.CheckResult(
//                OffRegApi.ORGetKeySecurity(key.Handle, securityInformation_, pSecurityDescriptor_, lpcbSecurityDescriptor_));
        }
    }
}
