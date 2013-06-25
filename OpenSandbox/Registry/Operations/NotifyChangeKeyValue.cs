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
    internal static class NotifyChangeKeyValueExtension
    {
        internal static void NotifyChangeKeyValue(
            this VirtualKey key,
            bool watchSubtree,
            Win32Api.REG_NOTIFY_CHANGE notifyFilter,
            IntPtr hEvent,
            bool asynchronous)
        {
            if (!key.TryApplyOperation(KeyDisposition.WINDOWS_REG, null,
                new KeySecurity(Win32Api.KeySecurity.KEY_NOTIFY),
                keyImpl => keyImpl.TryApply(new NotifyChangeKeyValue(watchSubtree, notifyFilter,
                    hEvent, asynchronous))))
            {
                throw new FileNotFoundException();
            }
        }
    }

    internal class NotifyChangeKeyValue : IKeyImplHandler
    {
        private bool watchSubtree_;
        private Win32Api.REG_NOTIFY_CHANGE notifyFilter_;
        private IntPtr hEvent_;
        private bool asynchronous_;

        internal NotifyChangeKeyValue(
            bool watchSubtree,
            Win32Api.REG_NOTIFY_CHANGE notifyFilter,
            IntPtr hEvent,
            bool asynchronous)
        {
            watchSubtree_ = watchSubtree;
            notifyFilter_ = notifyFilter;
            hEvent_ = hEvent;
            asynchronous_ = asynchronous;
        }

        public bool Handle(WindowsKey key)
        {
            return Win32Exception.CheckIfFoundAndNoError(
                Win32Api.RegNotifyChangeKeyValue(key.Handle, watchSubtree_, notifyFilter_, hEvent_,
                asynchronous_));
        }

        public bool Handle(OffRegKey key)
        {
            // TODO: implement for Offreg keys
            return false;
        }
    }
}
