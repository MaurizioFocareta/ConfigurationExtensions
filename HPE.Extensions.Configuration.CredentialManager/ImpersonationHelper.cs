using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Security.Principal;
using static HPE.Extensions.Configuration.CredentialManager.NativeMethods;

namespace HPE.Extensions.Configuration.CredentialManager
{
    public static class ImpersonationHelper
    {
        private static void EnablePrivileges(params string[] names)
        {
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                                  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                  out IntPtr hToken))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");
            }

            try
            {
                foreach (var name in names)
                {
                    if (!LookupPrivilegeValue(null, name, out LUID luid))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), $"LookupPrivilegeValue({name}) failed");
                    }

                    var tp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privileges = new LUID_AND_ATTRIBUTES
                        {
                            Luid = luid,
                            Attributes = SE_PRIVILEGE_ENABLED
                        }
                    };

                    if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), $"AdjustTokenPrivileges({name}) failed");
                    }

                    int err = Marshal.GetLastWin32Error();
                    if (err == ERROR_NOT_ALL_ASSIGNED)
                    {
                        throw new Win32Exception(err, $"AdjustTokenPrivileges({name}) failed to assign privilege");
                    }
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }
        private static int FindProcessId(string name)
        {
            foreach (var p in Process.GetProcessesByName(name.Replace(".exe", "")))
            {
                return p.Id;
            }
            return 0;
        }

        /// <summary>
        /// Impersonates the given user and runs <paramref name="action"/> in that context.
        /// Requires the current process to be elevated; enables SeBackup/SeRestore/SeImpersonate to load the profile.
        /// </summary>
        public static void RunAs(string domain, string user, SecureString securePassword, Action action, bool noUi = true)
        {
            if (action == null)
            {
                throw new ArgumentNullException(nameof(action));
            }

            if (securePassword == null || securePassword.Length == 0)
            {
                throw new ArgumentException("Password cannot be empty.", nameof(securePassword));
            }

            // Enable required privileges in the caller *before* LoadUserProfile
            EnablePrivileges("SeBackupPrivilege", "SeRestorePrivilege", "SeImpersonatePrivilege");

            IntPtr pwd = IntPtr.Zero;
            SafeAccessTokenHandle token = null;

            try
            {
                pwd = Marshal.SecureStringToGlobalAllocUnicode(securePassword);

                if (!LogonUser(user, domain, pwd,
                               LOGON32_LOGON_INTERACTIVE,
                               LOGON32_PROVIDER_DEFAULT,
                               out token))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed");
                }

                var pi = new PROFILEINFO
                {
                    dwSize = Marshal.SizeOf<PROFILEINFO>(),
                    dwFlags = noUi ? PI_NOUI : 0,
                    lpUserName = user,
                    lpProfilePath = null,
                    lpDefaultPath = null,
                    lpServerName = null,
                    lpPolicyPath = null,
                    hProfile = IntPtr.Zero
                };

                if (!LoadUserProfile(token, ref pi))
                {
                    var err = Marshal.GetLastWin32Error();
                    throw new Win32Exception(err, $"LoadUserProfile failed ({err}). Ensure the process is elevated and has SeBackup/SeRestore privileges.");
                }

                try
                {
#pragma warning disable CA1416 // Validate platform compatibility
                    WindowsIdentity.RunImpersonated(token, action);
#pragma warning restore CA1416 // Validate platform compatibility
                }
                finally
                {
                    // Always unload the user profile when done
                    if (pi.hProfile != IntPtr.Zero)
                    {
                        if (!UnloadUserProfile(token, pi.hProfile))
                        {
                            var err = Marshal.GetLastWin32Error();
                            // You may want to log this but not throw in finally
                            Debug.WriteLine($"UnloadUserProfile failed: {err}");
                        }
                    }
                }
            }
            finally
            {
                if (pwd != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(pwd);
                }

                token?.Dispose();
            }
        }

        public static void RunAsLocalSystem(Action action, bool noUi = true)
        {
            EnablePrivileges("SeDebugPrivilege");

            var processId = FindProcessId("winlogon");
            if (processId != 0)
            {
                IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryInformation, false, processId);
                if (hProcess == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed.");
                }

                if (!OpenProcessToken(hProcess, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out IntPtr tokenHandle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed.");
                }

                SECURITY_ATTRIBUTES sa = default;
                sa.nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>();

                if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenImpersonation, out SafeAccessTokenHandle tokenDuplicated))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed.");
                }

                try
                {
#pragma warning disable CA1416 // Validate platform compatibility
                    WindowsIdentity.RunImpersonated(tokenDuplicated, action);
#pragma warning restore CA1416 // Validate platform compatibility
                }
                finally
                {
                    RevertToSelf();

                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    if (tokenHandle != IntPtr.Zero) CloseHandle(tokenHandle);
                    tokenDuplicated?.Dispose();
                }
            }
            else
            {
                throw new InvalidOperationException("Services.exe not found.");
            }
        }
    }
}
