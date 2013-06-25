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
using System.Linq;
using System.Text;
using OffregLib;
using OpenSandbox.Logging;

namespace OpenSandbox.Registry
{
    internal interface IHKeyFactory : IDisposable
    {
        int AllocHandle();
        void FreeHandle(int handle);
    }

    internal class FakeHKeyFactory : IHKeyFactory
    {
        public void Dispose()
        {
            nextHandle_ = 0x44444444;
        }

        // TODO: if some of the HKEYs returned by VirtualRegistry are used after it is
        // shutdown, for instance in the ExitProcess (DllMains of different DLLs), etc.
        // then this offset value leads to access violations and crash.
        // Consider smth like opening HKEYs in Windows registry like many HKEYS to HKEY_CLASSES_ROOT
        // and using them for those cases there's no key in windows registry wich is in Offreg.
        // We do not modify windows registry so if we opened HKEY there, it is not ever deleted.
        private int nextHandle_ = 0x44444444; // We assume native HKEYs never reach this value

        public int AllocHandle()
        {
            DebugLogger.WriteLine("SUCCESS: FakeHKeyFactory allocates a new handle");
            // TODO: call some native Reg* function or NtQueryKey and check that
            // it returns ERROR_INVALUD_HANDLE against the handle, otherwise
            // return some different handle
            return nextHandle_++;
        }

        public void FreeHandle(int handle)
        {
            // Do nothing
        }
    }


    // The factory creates HKEY using initial RegOpenKeyEx( HKEY_CURRENT_USER, "Software", ... ) and 
    // then returns a duplicate of that handle.
    // Obtained handle is able to use when the sandbox is unloaded ( with fail result, sure )
    // so the application will not crash like it would be when we using a fake hkey
    internal class SystemHKeyFactory : IHKeyFactory
    {
        private IntPtr seedHKey_ = System.IntPtr.Zero;
        private Stack<int> handlesToReuse_ = new Stack<int>();
        private List<IntPtr> handlesToClose_ = new List<IntPtr>();

        public SystemHKeyFactory()
        {
            int result = Win32Api.RegOpenKeyEx((IntPtr)Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER, "Software",
                                                0, Win32Api.KeySecurity.KEY_QUERY_VALUE, out seedHKey_);
            if ( (Win32Result)result != Win32Result.ERROR_SUCCESS )
                throw Win32Exception.Create( result );
        }

        public void Dispose()
        {
            foreach (IntPtr handle in handlesToClose_)
            {
                Win32Api.CloseHandle(handle);
            }

            handlesToClose_.Clear();
            handlesToReuse_.Clear();
        }

        public int AllocHandle()
        {
            if (handlesToReuse_.Count > 0)
            {
                return handlesToReuse_.Pop();
            }

            IntPtr duplicate = System.IntPtr.Zero;
            bool result = Win32Api.DuplicateHandle(Win32Api.GetCurrentProcess(), seedHKey_, Win32Api.GetCurrentProcess(), out duplicate,
                                        0, false, (uint)Win32Api.DuplicateOptions.DUPLICATE_SAME_ACCESS);
            if (!result)
            {
                DebugLogger.WriteLine("ERROR: SystemHKeyFactory Can't allocate a new handle");
                return 0;
            }

            handlesToClose_.Add(duplicate);

            return (int)duplicate;
        }

        public void FreeHandle(int handle)
        {
            handlesToReuse_.Push(handle);
        }
    }
}
