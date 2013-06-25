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
using System.Threading;

namespace OpenSandbox.Registry
{
    /// <summary>Regular reghive saver helper class -- active object.</summary>
    /// <para>Every n milliseconds (by default 1000) checks if the "diff" hive
    /// was modified and if it was, saves it to disk. This is needed to avoid data loss
    /// in case of crash/unhandled exception on app exit.</para>
    /// <para>Singleton to make it work with tests where Shutdown is not called.</para>
    internal class RegularHiveSaver : ThreadBase
    {
        private VirtualRegistry registry_;
        private int intervalMs_;
        private EventWaitHandle finished_ = new AutoResetEvent(false);

        public RegularHiveSaver(VirtualRegistry registry, int intervalMs = 1000)
        {
            registry_ = registry;
            intervalMs_ = intervalMs;
            StartThread();
        }

        protected override void ThreadProc()
        {
            while (!finished_.WaitOne(intervalMs_))
            {
                registry_.Save();
            }
        }

        protected override void DisposeUnmanaged()
        {
            finished_.Set();
            //thread_.Join(); // Experimental. Theoretically a problem might be only in case
            // if thread exits in the middle of ORSaveHive so that hive is left corrupted,
            // but it should be so rare...
            // However .NET hangs on join if exiting from .NET target app.

            // TODO: the comment above was written before the thread was made IsBackground = true,
            // may be now join is safe, check
        }
    }
}
