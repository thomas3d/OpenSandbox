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

namespace OpenSandbox
{
    internal class HGlobalPtr : DisposableBase
    {
        private IntPtr ptr_;

        internal HGlobalPtr(int size)
        {
            if (size == 0)
            {
                ptr_ = IntPtr.Zero;
            }
            else
            {
                ptr_ = Marshal.AllocHGlobal(size);
            }
        }

        internal HGlobalPtr(uint size)
            : this(unchecked((int)size))
        {}

        internal HGlobalPtr(IntPtr allocatedPtr)
        {
            ptr_ = allocatedPtr;
        }

        internal IntPtr Ptr { get { return ptr_; } }

        protected override void DisposeUnmanaged()
        {
            if (ptr_ != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ptr_);
                ptr_ = IntPtr.Zero;
            }
        }
    }
}
