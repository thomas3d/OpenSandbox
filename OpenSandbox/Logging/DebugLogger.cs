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
using System.IO;

namespace OpenSandbox.Logging
{
    internal class AsyncDebugLogger : AsyncLogger
    {
        // Make sure it is set to false when checked in to SVN
        // Otherwise it hits performance drastically
        private const bool FLUSH_EVERY_MESSAGE = false;
        private bool enabled_ = false;

        public bool Enabled { get { return enabled_; } }

        public AsyncDebugLogger(ILogger logger)
            : base(logger)
        { }

        protected override void ThreadStarted()
        {
            base.ThreadStarted();
            // Reading settings in thread because file hooks are disabled in threads and
            // otherwise this might result in UB because of reenterance or lock
            string file = "Settings.xml";
            try
            {
                enabled_ = File.ReadAllText(file).ToLower().Contains("<logging>on</logging>");
            }
            catch { }
        }

        internal override void WriteItem(string format, params object[] args)
        {
            if (enabled_)
            {
                base.WriteItem(format, args);
                if (FLUSH_EVERY_MESSAGE) ForceFlush();
            }
        }
    }

    internal class DebugLogger
    {
        private static AsyncDebugLogger fflDebug;

        static DebugLogger()
        {
            try
            {
                fflDebug = new AsyncDebugLogger(new FileLogger(
                        Path.Combine(Utils.GetExeDir(), "regcalls.log")));
            }
            catch
            {
                // Perhaps access denied to open file. Well fflDebug is null, so logging is disabled.
            }
        }

        internal static void WriteLine(string format, params object[] args)
        {
            try
            {
                if (fflDebug != null)
                    fflDebug.WriteItem(format, args);
            }
            catch { }
        }

        internal static void SafeDispose()
        {
            try
            {
                if (fflDebug != null)
                    fflDebug.Dispose();
            }
            catch { }
        }

        internal static bool DoLogging
        {
            get { return fflDebug != null && fflDebug.Enabled; }
        }
    }
}
