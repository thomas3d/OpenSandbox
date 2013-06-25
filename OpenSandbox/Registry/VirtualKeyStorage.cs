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
using System.Threading;

namespace OpenSandbox.Registry
{
    internal class VirtualKeyStorage : DisposableBase
    {
        private ReaderWriterLock keysRwl = new ReaderWriterLock();
        private Dictionary<int, VirtualKey> keys_ = new Dictionary<int, VirtualKey>();
        private IHKeyFactory hkeyFactory_ = new SystemHKeyFactory();

        internal VirtualKeyStorage(VirtualRegistry registry)
        {
            foreach (Win32Api.RegPredefinedKeys key
                in Enum.GetValues(typeof(Win32Api.RegPredefinedKeys)))
            {
                keys_.Add((int)key, registry.CreatePredefinedKey((IntPtr)key));
            }
        }

        // Thread-safe
        internal VirtualKey Get(IntPtr hKey)
        {
            keysRwl.AcquireReaderLock(Timeout.Infinite);
            try
            {

                int handle = ToHandle(hKey);
                if (!keys_.ContainsKey(handle)) return null;
                return keys_[handle];
            }
            finally
            {
                keysRwl.ReleaseReaderLock();
            }
        }

        // Takes responsibility of the key ownership
        // if key is not added to the storage, it gets closed
        // But for now this never happens
        internal IntPtr Add(VirtualKey key)
        {
            keysRwl.AcquireWriterLock(Timeout.Infinite);
            try
            {
                int newHandle = hkeyFactory_.AllocHandle();
                keys_.Add(newHandle, key);
                return FromHandle(newHandle);
            }
            finally
            {
                keysRwl.ReleaseWriterLock();
            }
        }

        internal void Add(IntPtr hKey, VirtualKey key)
        {
            keysRwl.AcquireWriterLock(Timeout.Infinite);
            try
            {
                keys_.Add(ToHandle(hKey), key);
            }
            finally
            {
                keysRwl.ReleaseWriterLock();
            }
        }

        internal void Remove(IntPtr hKey)
        {
            keysRwl.AcquireWriterLock(Timeout.Infinite);
            try
            {
                int handle = ToHandle(hKey);
                keys_.Remove(handle);
                hkeyFactory_.FreeHandle(handle);
            }
            finally
            {
                keysRwl.ReleaseWriterLock();
            }
        }

        private static int ToHandle(IntPtr hKey)
        {
            int handle = (int)hKey;
            Debug.Assert((IntPtr)handle == hKey);
            return handle;
        }

        private static IntPtr FromHandle(int handle)
        {
            IntPtr hKey = (IntPtr)handle;
            Debug.Assert((int)hKey == handle);
            return hKey;
        }

        protected override void DisposeManaged()
        {
            foreach (KeyValuePair<int, VirtualKey> kv in keys_)
            {
                kv.Value.Dispose();
            }
            // For safety against the second call of Dispose
            keys_.Clear();

            hkeyFactory_.Dispose();
        }
    }
}
