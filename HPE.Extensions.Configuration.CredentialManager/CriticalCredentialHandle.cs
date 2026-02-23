using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static HPE.Extensions.Configuration.CredentialManager.NativeMethods;

namespace HPE.Extensions.Configuration.CredentialManager
{
    /// <summary>
    /// Safe handle wrapper for unmanaged credential memory allocated by the Windows Credential API.
    /// Ensures native credential buffers (including sensitive credential blobs) are securely zeroed
    /// before being freed.
    /// </summary>
    internal sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
    {
        private readonly uint _enumerationCount;

        /// <summary>
        /// Creates a handle for a single credential (from CredRead).
        /// </summary>
        internal CriticalCredentialHandle(IntPtr preexistingHandle)
        {
            SetHandle(preexistingHandle);
            _enumerationCount = 0;
        }

        /// <summary>
        /// Creates a handle for an enumeration result (from CredEnumerate).
        /// </summary>
        /// <param name="preexistingHandle">Pointer to the credential array.</param>
        /// <param name="enumerationCount">Number of credentials in the array.</param>
        internal CriticalCredentialHandle(IntPtr preexistingHandle, uint enumerationCount)
        {
            SetHandle(preexistingHandle);
            _enumerationCount = enumerationCount;
        }

        /// <summary>
        /// Reads a single credential from the native handle.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when the handle is invalid.</exception>
        internal CREDENTIAL GetCredential()
        {
            if (!IsInvalid)
            {
                // Get the Credential from the mem location
                return Marshal.PtrToStructure<CREDENTIAL>(handle);
            }
            else
            {
                throw new InvalidOperationException("Invalid CriticalHandle!");
            }
        }

        /// <summary>
        /// Reads multiple credentials from the native handle (enumeration result).
        /// </summary>
        /// <param name="size">Number of credentials to read.</param>
        /// <exception cref="InvalidOperationException">Thrown when the handle is invalid.</exception>
        internal CREDENTIAL[] EnumerateCredentials(uint size)
        {
            if (!IsInvalid)
            {
                var credentialArray = new CREDENTIAL[size];

                for (int i = 0; i < size; i++)
                {
                    IntPtr ptrPlc = Marshal.ReadIntPtr(handle, i * IntPtr.Size);

                    var nc = Marshal.PtrToStructure<CREDENTIAL>(ptrPlc);

                    credentialArray[i] = nc;
                }

                return credentialArray;
            }
            else
            {
                throw new InvalidOperationException("Invalid CriticalHandle!");
            }
        }

        /// <summary>
        /// Securely zeros credential blobs in native memory, then frees the handle via CredFree.
        /// Uses RtlZeroMemory via P/Invoke to prevent JIT dead store elimination.
        /// </summary>
        override protected bool ReleaseHandle()
        {
            // If the handle was set, free it. Return success.
            if (!IsInvalid)
            {
                // Zero credential blobs before freeing — prevents sensitive data from
                // lingering in freed memory pages.
                ZeroCredentialBlobs();
                
                CredFree(handle);
                // Mark the handle as invalid for future users.
                SetHandleAsInvalid();
                return true;
            }
            // Return false. 
            return false;
        }

        private void ZeroCredentialBlobs()
        {
            try
            {
                if (_enumerationCount == 0)
                {
                    // Single credential (from CredRead)
                    ZeroSingleCredentialBlob(handle);
                }
                else
                {
                    // Enumeration (from CredEnumerate) — handle is array of pointers
                    for (uint i = 0; i < _enumerationCount; i++)
                    {
                        IntPtr ptr = Marshal.ReadIntPtr(handle, (int)(i * (uint)IntPtr.Size));
                        ZeroSingleCredentialBlob(ptr);
                    }
                }
            }
            catch
            {
                // Best-effort zeroing — don't prevent CredFree on failure
            }
        }

        private static void ZeroSingleCredentialBlob(IntPtr credPtr)
        {
            var ncred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);

            if (ncred.CredentialBlob != IntPtr.Zero && ncred.CredentialBlobSize > 0)
            {
                SecureZeroMemory(ncred.CredentialBlob, new UIntPtr(ncred.CredentialBlobSize));
            }
        }
    }
}
