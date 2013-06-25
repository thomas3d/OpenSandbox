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
//using System.Runtime.ConstrainedExecution;

namespace OpenSandbox.Registry
{
    internal class KeyImplHolder : DisposableBase //CriticalFinalizerObject, IDisposable
    {
        private IKeyImpl keyImpl_;
//        private string debugCreationCallStack_;

        internal KeyImplHolder(IKeyImpl keyImpl)
        {
            keyImpl_ = keyImpl;
//            debugCreationCallStack_ = Environment.StackTrace;
        }

        internal IKeyImpl GetKeyImpl()
        {
            return keyImpl_;
        }

        internal IKeyImpl ReleaseKeyImpl()
        {
            IKeyImpl result = keyImpl_;
            keyImpl_ = null;
            return result;
        }

        protected /*virtual*/override void DisposeUnmanaged()
        {
            if (keyImpl_ != null)
            {
                // Ignoring errors such as closing a predefined key
                try
                {
                    keyImpl_.Close();
                }
                catch { }
                keyImpl_ = null;
            }
        }
/*
        public void Dispose()
        {
            DisposeUnmanaged();
        }

        ~KeyImplHolder()
        {
            DisposeUnmanaged();
        }
*/
    }

    internal class NotOwningKeyImplHolder : KeyImplHolder
    {
        internal NotOwningKeyImplHolder(IKeyImpl keyImpl)
            : base(keyImpl)
        { }

        protected override void DisposeUnmanaged() { }
    }

    // The purpose of the cache is significant speed improvement in the following scenario:
    // 1. VirtualKey.operation is called.
    // 2. It opens appropriate KeyImpl basing on identity, subKey and disposition
    // 3. Performs operation in the KeyImpl
    // 4. Closes KeyImpl

    // Until now VirtualKey optimized 2 and 4 by allowing to open impl for each disposition
    // once during the lifetime of virtual key.
    // Important thing is that all cached impls were closed when the key was closed.

    // Now we need to think out the lifetime of cached impls.

    // 1. When VirualKey is closed, all the impls associated with it should be closed.
    // So may be global cache is not what we need.
    // 2. We could implement reference counting for the impls, but debugging will be much more complex.

    // Consideration: when the virtual registry is closed, nobody can close any keys anymore, because
    // our virtual HKEYs are invalid in windows environment. Why not to close them if they were not closed?
    // well they will be anyway closed on process exit, may be this is intention of the target process
    // to postpone closing till that moment.

    // What are the advantages of the global cache compared to per-virtual key caches?
    internal class KeyImplCache : DisposableBase
    {
        private struct CacheKey
        {
            public KeyIdentity Identity;
            public KeyDisposition Disposition;

            public override int GetHashCode()
            {
                return Identity.GetHashCode() ^ Disposition.GetHashCode();
            }

            public override bool Equals(object obj)
            {
                return obj is CacheKey && this == (CacheKey)obj;
            }

            public static bool operator ==(CacheKey first, CacheKey second)
            {
                if (((object)first == null) || ((object)second == null))
                {
                    return ((object)first == null) == ((object)second == null);
                }
                return first.Identity == second.Identity && first.Disposition == second.Disposition;
            }

            public static bool operator !=(CacheKey first, CacheKey second)
            {
                return !(first == second);
            }
        }

        private Dictionary<CacheKey, KeyImplHolder> cachedKeyImpls_ =
            new Dictionary<CacheKey, KeyImplHolder>();

        // If the keyImpl is added, returns NotOwningKeyImplHolder,
        // otherwise returns original KeyImplHolder
        public KeyImplHolder Add(KeyIdentity identity, KeyDisposition disposition, KeyImplHolder keyHolder)
        {
            lock (this)
            {
                CacheKey cacheKey = new CacheKey { Identity = identity, Disposition = disposition };
                if (cachedKeyImpls_.ContainsKey(cacheKey)) return keyHolder;
                cachedKeyImpls_.Add(cacheKey, keyHolder);
                return new NotOwningKeyImplHolder(keyHolder.GetKeyImpl());
            }
        }

        // Returns keyImpl owned by cache, thus KeyHolder is not used
        public IKeyImpl TryGet(KeyIdentity identity, KeyDisposition disposition, KeySecurity samDesired)
        {
            lock (this)
            {
                CacheKey cacheKey = new CacheKey { Identity = identity, Disposition = disposition };
                if (!cachedKeyImpls_.ContainsKey(cacheKey)) return null;

                KeyImplHolder cached = cachedKeyImpls_[cacheKey];
                if (!samDesired.IsSubSetOf(cached.GetKeyImpl().GetAccessMode())) return null;

                return cached.GetKeyImpl();
            }
        }

        public void Clear()
        {
            foreach (KeyValuePair<CacheKey, KeyImplHolder> kvp in cachedKeyImpls_)
            {
                kvp.Value.Dispose();
            }
            cachedKeyImpls_.Clear();
        }

        protected override void DisposeManaged()
        {
            Clear();
        }
    }
}