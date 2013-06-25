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
using System.Reflection;
using System.Threading;
using System.IO;

namespace RoozzNETSandboxingHost
{
    class Program
    {
        [STAThread] // This is needed for WPF apps, not sure about other 
            //TODO: would there be a case where MTA is needed?
            //"they must protect their internal state against concurrent calls, in case they're loaded in the MTA, but must not block, in case they're loaded in an STA."
            //http://stackoverflow.com/a/127340/66372
            //"If you're only going to consume COM components all that you really need to know is that you have to match the apartment to the component or nasty things will happen."
            //http://stackoverflow.com/a/485109/66372
        static void Main(string[] args)
        {
            string OSBOXPARAMS = Environment.GetEnvironmentVariable("OSBOXPARAMS");
            int delimPos = OSBOXPARAMS.IndexOf(" ");
            //TODO: could an access violation exception be coming from .OpenExisting - http://msdn.microsoft.com/en-US/library/530zssyk(v=VS.80).aspx
            //  i.e. "If you run the compiled example from two command windows, the second copy will throw an access violation exception on the call to OpenExisting(String)."
            EventWaitHandle injectionDone = EventWaitHandle.OpenExisting(OSBOXPARAMS.Substring(0, delimPos));
            string assemblyPath = OSBOXPARAMS.Substring(delimPos + 2, OSBOXPARAMS.Length - delimPos - 3); // assumming path is quoted
            // Waiting until injection is done
            injectionDone.WaitOne();

            AppDomainSetup ads = new AppDomainSetup();
            ads.ApplicationBase = System.Environment.CurrentDirectory;
            ads.ConfigurationFile = assemblyPath + ".config";

            AppDomain ad2 = AppDomain.CreateDomain("AD #2", null, ads);
//            Assembly title = Assembly.LoadFile(assemblyPath);
            // Removing first item from the list of arguments
//            args = args.Where((val, idx) => idx > 1).ToArray();
            // System.Windows.Forms.MessageBox.Show("before");
            ad2.ExecuteAssembly(assemblyPath, args);
            AppDomain.Unload(ad2);
/*            object[] parameters = new object[0];
            if (title.EntryPoint.GetParameters().Length > 0)
            {
                parameters = new object[] { args };
            }
            title.EntryPoint.Invoke(null, parameters);
*/
        }
    }
}
