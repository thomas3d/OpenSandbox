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

namespace OpenSandbox.Registry
{
    internal class KeySecurity
    {
        private Win32Api.KeySecurity value_;

        public KeySecurity(Win32Api.KeySecurity value)
        {
            value_ = value;
        }

        public Win32Api.KeySecurity Value { get { return value_; } }

        public static void ExtractWow64Options(Win32Api.KeySecurity value,
            out KeySecurity keySecurity, out Win32Api.RegWow64Options wow64Options)
        {
            wow64Options = (Win32Api.RegWow64Options)((int)value &
                (int)(Win32Api.RegWow64Options.KEY_WOW64_32KEY | Win32Api.RegWow64Options.KEY_WOW64_64KEY));
            keySecurity = new KeySecurity(value & (Win32Api.KeySecurity)~wow64Options);
        }

        internal bool IsOnlyForRead()
        {
            return ((int)value_ & ~(int)Win32Api.KeySecurity.KEY_READ) == 0 ||
                value_ == Win32Api.KeySecurity.MAXIMUM_ALLOWED;
        }

        public bool IsSubSetOf(KeySecurity another)
        {
            // During refactoring in the next line
            // (value_ & ~another.value_) != 0 was replaced with (value_ & ~another.value_) == 0
            // this may be wrong (althoug looks like it was a bug and now it should be fixed)
            // so please keep an eye on this change
            return ((value_ & ~another.value_) == 0 ||
                value_ == Win32Api.KeySecurity.MAXIMUM_ALLOWED ||
                another.value_ == Win32Api.KeySecurity.MAXIMUM_ALLOWED);
        }

        public void RelaxToReadAccess()
        {
            value_ = (Win32Api.KeySecurity)((int)value_ & (int)Win32Api.KeySecurity.KEY_READ);
            Debug.Assert(IsOnlyForRead());
        }
    }
}
