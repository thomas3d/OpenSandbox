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
using OpenSandbox.Logging;
using OpenSandbox.Registry;
using System.Collections.Generic;

namespace OpenSandbox
{
    internal class PathRebaser
    {
        internal class FindFileHolder : DisposableBase
        {
            public IntPtr Handle { get; private set; }

            public FindFileHolder(IntPtr handle)
            {
                Handle = handle;
            }

            protected override void DisposeUnmanaged()
            {
                if (Handle != Win32Api.INVALID_HANDLE_VALUE)
                    Win32Api.FindClose(Handle);
            }
        }
        // precondition: filename contains neither directory nor disk drive, only "leaf" filename
        // precondition: folder contains full path
        internal static void GetFilesAndFolders(string folder, string filename, HashSet<string> folders, HashSet<string> files)
        {
            Win32Api.WIN32_FIND_DATA findData;

            if (folder.EndsWith(@"\")) folder = folder.Remove(folder.Length - 1);

            // First searching for exact file/folder name match
            using (FindFileHolder byNameHandle = new FindFileHolder(
                Win32Api.FindFirstFileEx(@"\\?\" + folder + @"\" + filename,
                    Win32Api.FINDEX_INFO_LEVELS.FindExInfoStandard,
                    out findData,
                    Win32Api.FINDEX_SEARCH_OPS.FindExSearchNameMatch,
                    IntPtr.Zero, 0)))
            {
                if (byNameHandle.Handle != Win32Api.INVALID_HANDLE_VALUE)
                {
                    do
                    {
                        string fullName = folder + @"\" + findData.cFileName;
                        if ((findData.dwFileAttributes & FileAttributes.Directory) != 0)
                            folders.Add(fullName);
                        else
                            files.Add(fullName);
                    }
                    while (Win32Api.FindNextFile(byNameHandle.Handle, out findData));
                }
            }
            // Then traversing subdirs
            using (FindFileHolder subdirHandle = new FindFileHolder(
                Win32Api.FindFirstFileEx(@"\\?\" + folder + @"\*",
                    Win32Api.FINDEX_INFO_LEVELS.FindExInfoStandard,
                    out findData,
                    Win32Api.FINDEX_SEARCH_OPS.FindExSearchLimitToDirectories,
                    IntPtr.Zero, 0)))
            {
                if (subdirHandle.Handle != Win32Api.INVALID_HANDLE_VALUE)
                {
                    do
                    {
                        if ((findData.dwFileAttributes & FileAttributes.Directory) != 0)
                        {

                            if (findData.cFileName != "." && findData.cFileName != "..")
                            {
                                string subdirectory = folder + @"\" + findData.cFileName;

                                GetFilesAndFolders(subdirectory, filename, folders, files);
                            }
                        }
                    }
                    while (Win32Api.FindNextFile(subdirHandle.Handle, out findData));
                }
            }
        }

        private FileSystemWatcher watcher_ = new FileSystemWatcher(Utils.GetRootSearchDir());
        private HashSet<string> files_ = new HashSet<string>();
        private HashSet<string> folders_ = new HashSet<string>();

        public PathRebaser()
        {
            InitCache();
            watcher_.NotifyFilter = NotifyFilters.CreationTime | NotifyFilters.DirectoryName | NotifyFilters.FileName;
            watcher_.Created += new FileSystemEventHandler(OnFileStructureChange);
            watcher_.Deleted += new FileSystemEventHandler(OnFileStructureChange);
            watcher_.Renamed += new RenamedEventHandler(OnFileRenamed);
            watcher_.Error += new ErrorEventHandler(OnWatchingError);
            watcher_.IncludeSubdirectories = true;
            watcher_.EnableRaisingEvents = true;
        }

        private void OnFileStructureChange(object source, FileSystemEventArgs args)
        {
            lock (this)
            {
                if (args.ChangeType == WatcherChangeTypes.Created)
                {
                    if (Directory.Exists(args.FullPath))
                        folders_.Add(args.FullPath);
                    else
                        files_.Add(args.FullPath);
                }
                if (args.ChangeType == WatcherChangeTypes.Deleted)
                {
                    folders_.Remove(args.FullPath);
                    files_.Remove(args.FullPath);
                }
            }
        }

        private void OnFileRenamed(object source, RenamedEventArgs args)
        {
            lock (this)
            {
                if (Directory.Exists(args.FullPath))
                {
                    folders_.Remove(args.OldFullPath);
                    folders_.Add(args.FullPath);
                }
                else
                {
                    files_.Remove(args.OldFullPath);
                    files_.Add(args.FullPath);
                }
            }
        }

        private void OnWatchingError(object source, ErrorEventArgs args)
        {
            lock (this)
            {
                folders_.Clear();
                files_.Clear();
                InitCache();
            }
        }

        private void InitCache()
        {
            GetFilesAndFolders(Utils.GetRootSearchDir(), "*", folders_, files_);
        }

        private void GetFilesAndFoldersFromCache(string filename, List<string> folders, List<string> files)
        {
//            watcher_.WaitForChanged(WatcherChangeTypes.All, 0);
            lock (this)
            {
                foreach (string file in files_)
                {
                    if (string.Compare(Path.GetFileName(file), filename, ignoreCase: true) == 0)
                        files.Add(file);
                }
                foreach (string folder in folders_)
                {
                    if (string.Compare(Path.GetFileName(folder), filename, ignoreCase: true) == 0)
                        files.Add(folder);
                }
            }
        }

        /// <summary>
        /// Registry string value alterer which makes virtual registry rebase path string values
        /// to the current directory or subdirs if the file exists there.
        /// </summary>
        /// <param name="value">string value being read</param>
        /// <returns>altered string value</returns>
        internal string RebasePath(KeyIdentity key, string valueName, string value)
        {
            // Performance heuristic: return if it has no path or file name components inside the string. 
            if (!(value.Contains("\\") || value.Contains(".")))
                return value;
            // Performance heuristic: return if it is version/progid in HKCR
            if ((key.BaseKey == (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CLASSES_ROOT
                || (key.BaseKey == (IntPtr)Win32Api.RegPredefinedKeys.HKEY_CURRENT_USER
                    && key.GetRegPath().StartsWith(@"Software\Classes\", StringComparison.CurrentCultureIgnoreCase))))
            {
                if (string.Compare(valueName, "Version", ignoreCase: true) == 0
                    || string.Compare(valueName, "Progid", ignoreCase: true) == 0
                    // InprocServer32 value is not the same as default value of InprocServer32 key
                    // and it contains not a path but "Darwin Descriptor" used by installer
                    || string.Compare(valueName, "InprocServer32", ignoreCase: true) == 0)
                    return value;
                if (string.IsNullOrEmpty(valueName)
                    && key.GetRegPath().EndsWith(@"\Progid", StringComparison.CurrentCultureIgnoreCase))
                    return value;
            }

            value = value.TrimEnd('\\');//some of the code below depends on a trailing \ not being there

            // Checking if it is a path and the path exists
            if (File.Exists(value) || Directory.Exists(value))
            {
                DebugLogger.WriteLine("RebasePath skipped, path already exists: {0}", value);
                return value;
            }
            string filename;
            try
            {
                filename = Path.GetFileName(value);
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine("RebasePath failed {0} ex: {1}", value, ex.Message);
                return value;
            }

            // Checking if file pointed by path exists in the directory where .exe resides
            try
            {
                //TODO: this is expensive, do it once for the whole process i.e. cache list of directories and files after first retrieval ... check impact in memory usage though
                //TODO: this can lead to *very* hard to debug situations. 
                //One special situation is filenames without extensions that could also map to the name of a folder in some other path
                //Another situation happened with 1379, a zip file contained a path c\program files\..., which can actually happen in some titles (although may have been due to auto conversion issues)
                //Another situation would be parts of paths that repeat in the tree, and rebasing a relative path ... we'd match the deepest one while there is no way to know the intended one
                string titleRoot = Utils.GetRootSearchDir();

                List<string> files = new List<string>();
                List<string> folders = new List<string>();
                GetFilesAndFoldersFromCache(filename, folders, files);

                var fileList = files.ToArray(); //Directory.GetFiles(titleRoot, filename, SearchOption.AllDirectories);
                if (fileList.Length > 0)
                {
                    string newFilePath = fileList[MaxMatch(fileList, value)];
                    DebugLogger.WriteLine("RebasePath {0} to: {1}", value, newFilePath);
                    return newFilePath;
                }
                var dirList = folders.ToArray(); //Directory.GetDirectories(titleRoot, filename, SearchOption.AllDirectories);
                if (dirList.Length > 0)
                {
                    string newFilePath = dirList[MaxMatch(dirList, value)];
                    DebugLogger.WriteLine("RebasePath {0} to: {1}", value, newFilePath);
                    return newFilePath;
                }
                DebugLogger.WriteLine("RebasePath failed to find {0}, title root: {1}, filename: {2}", value, titleRoot, filename);
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine("RebasePath failed to find {0} ex: {1}", value, ex.ToString());
                return value;
            }
            return value;
        }

        // find the index of the string in sequence with the maximum match to value (starting from the end)
        public static int MaxMatch(string[] sequence, string value)
        {
            if (sequence.Length == 1)
                return 0; // speed up, as this is true in most cases. 

            int maxIndex = -1;
            int maxValueLength = 0;

            int index = 0;
            foreach (string s in sequence)
            {
                int len = MatchLength(s, value);
                if (len > maxValueLength)
                {
                    maxIndex = index;
                    maxValueLength = len;
                }
                index++;
            }
            return maxIndex;
        }

        // find how many characters from the end of the string that match. 
        // not case sensetive
        private static int MatchLength(string a, string b)
        {//TODO: validate this won't fail with special chars in some languages
            a = a.ToLower();
            b = b.ToLower();
            int i = a.Length;
            int j = b.Length;
            int n = 0;
            while (i > 0 && j > 0)
            {
                if (a[--i] == b[--j])
                    n++;
                else
                    break;
            }

            return n;
        }
    }
}