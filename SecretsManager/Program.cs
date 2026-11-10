using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;

namespace SecretsManager
{
    internal class Program
    {
        private static IConfigurationRoot configuration;

        private static ActionType _actionType = ActionType.None;
        private static UserType userType = UserType.CurrentUser;

        private static bool _showPwd = false;
        
        private static string _targetName = null;
        private static string _targetUsername = null;
        private static SecureString _targetPassword = null;

        private static EventWaitHandle _waitEvent = null;
        private static StreamWriter _logChannel = null;

        private static bool _impersonate = false;

        private static string _impersonateUser = null;

        private static void ShowHelp()
        {
            Console.WriteLine("Secrets Manager in Windows CredentialManager (HPE 2024)");
            Console.WriteLine($"Build: {Assembly.GetExecutingAssembly().GetName().Version}");
            Console.WriteLine();
            Console.WriteLine("SecretsManager [/u:user | /ls] [/w:<Target> | /e:<Target> | /a | /s:<Filter> | /d:<Target> | /p] [ /tu:<Username> /tp:<Password> | /bl:<BlobPath> ]");
            Console.WriteLine();
            Console.WriteLine("User impersonation context:");
            Console.WriteLine("/u\t\tThe action is performed in the context of the given user. Mutually exclusive with /ls.");
            Console.WriteLine("\t\t(You will be prompted for the password. This option requires elevated privileges).");
            Console.WriteLine("/ls\t\tThe action is performed in the context of local system account. Mutually exclusive with /u.");
            Console.WriteLine("\t\t(This option requires elevated privileges)");
            Console.WriteLine();
            Console.WriteLine("\t\tIf /u or /ls is not specified, the action is performed in the context of the current user.");
            Console.WriteLine("Actions:");
            Console.WriteLine("/w:<Target>\tAdd new generic credentials with the given <Target>.");
            Console.WriteLine("/e:<Target>\tEdit generic credentials with the given <Target>.");
            Console.WriteLine("/a\t\tGet all generic credentials.");
            Console.WriteLine("/s:<Filter>\tGet all generic credentials with Target starting with <Filter>.");
            Console.WriteLine("/d:<Target>\tRemoves the generic credentials with the given <Target>.");
            Console.WriteLine("/p\t\tGet all generic credentials with Target based on assembly attribute.");
            Console.WriteLine("\t\t(The assembly is searched for the CredentialManagerPrefixId attribute).");
            Console.WriteLine("Additional parameters:");
            Console.WriteLine("/tu:<Username>\tProvide the target username for /w and /e actions without prompt.");
            Console.WriteLine("/tp:<Password>\tProvide the target password for /w and /e actions without prompt.");
            Console.WriteLine("Flags:");
            Console.WriteLine("/sh\t\tShow secret passwords for /a and /s actions. Ignored for other actions.");
        }

        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
            }
            else
            {
                if (args[0] == "--attach")
                {
                    WaitForDebugger(30);
                    args = args.Skip(1).ToArray();
                }
                if (ParseParameters(args))
                {
                    Action action = null;
                    switch (_actionType)
                    {
                        case ActionType.ShowHelp:
                            ShowHelp();
                            break;
                        case ActionType.Search:
                            action = new Action(() => GetConfiguration(_targetName));
                            break;
                        case ActionType.SearchAll:
                            action = new Action(() => GetConfiguration(string.Empty));
                            break;
                        case ActionType.SearchAssembly:
                            action = new Action(() => GetConfiguration<Program>());
                            break;
                        case ActionType.Add:
                            GetTargetCredentials(false);
                            action = new Action(() => AddCredential());
                            break;
                        case ActionType.Edit:
                            GetTargetCredentials(true);
                            action = new Action(() => EditCredential(_targetName));
                            break;
                        case ActionType.Delete:
                            action = new Action(() => RemoveCredential(_targetName));
                            break;
                        default:
                            Console.WriteLine($"Select an action. Use /? or no argument for the help.");
                            break;
                    }

                    try
                    {
                        if (action != null)
                        {
                            if (_impersonate)
                            {
                                switch (userType)
                                {
                                    case UserType.LocalSystem:
                                        ImpersonationHelper.RunAsLocalSystem(action);
                                        break;
                                    case UserType.DifferentUser:
                                        var (user, domain, kind) = IdentityParser.DecideForLogonUser(_impersonateUser);
                                        if (kind == IdentityKind.DomainMSA)
                                        {
                                            Console.WriteLine($"Impersonating managed service account {domain}\\{user} with Scheduled Task. Waiting for task completion...");

                                            TaskSchedulerHelper.RunaAsManagedServiceAccount(domain, user, 
                                                _actionType, _targetName, _targetUsername, _targetPassword, _showPwd);
                                        }
                                        else
                                        {
                                            var impPwd = ReadPasswordSecure($"Password for user {_impersonateUser}: ", true);

                                            Console.WriteLine($"Impersonating account {domain}\\{user}...");

                                            ImpersonationHelper.RunAs(domain, user, impPwd, action);
                                        }
                                        break;
                                    default:
                                        Console.WriteLine($"Invalid user type for impersonation");
                                        break;
                                }
                            }
                            else
                            {
                                action();
                            }
                        }
                    }
                    finally
                    {
                        TaskSchedulerHelper.CloseNamedPipe(_logChannel);
                        TaskSchedulerHelper.SignalWaitEvent(_waitEvent);
                    }
                }
                else
                {
                    return -1;
                }
            }

            return 0;
        }

        static bool ParseParameters(string[] args)
        {
            foreach (var arg in args)
            {
                Regex argRegEx = new Regex("/(?<Switch>[A-Za-z?]{1,2}):?(?<Value>.*)?");
                var match = argRegEx.Match(arg);
                if (!match.Success)
                {
                    Console.WriteLine($"Invalid option - \"{arg}\"");
                    return false;
                }

                var action = match.Groups["Switch"].Value;
                var value = match.Groups["Value"].Value;

                if (!AppConstants.AllParameters.Contains(action))
                {
                    Console.WriteLine($"Unknown option - \"{action}\"");
                    return false;
                }

                if (_actionType != ActionType.None)
                {
                    if (AppConstants.ActionParameters.Contains(action))
                    {
                        Console.WriteLine($"Use only one option between /? /w /e /a /s /d /p");
                        return false;
                    }
                }

                switch (action)
                {
                    case "?":
                        _actionType = ActionType.ShowHelp;
                        break;
                    case "w":
                        _actionType = ActionType.Add;
                        _targetName = value;
                        if (string.IsNullOrEmpty(_targetName))
                        {
                            Console.WriteLine($"Missing target name in \"/w\" option");
                            return false;
                        }
                        break;
                    case "bl":
                        if (string.IsNullOrEmpty(value))
                        {
                            Console.WriteLine($"Missing blob path in \"/bl\" option");
                            return false;
                        }
                        var cred = TaskSchedulerHelper.ImportFromTempBlob(value);
                        if (cred != null)
                        {
                            _targetUsername = cred.Username;
                            _targetPassword = cred.SecurePassword;
                        }
                        else
                        {
                            Console.WriteLine($"Invalid blob path in \"/bl\" option");
                            return false;
                        }
                        break;
                    case "pp":
                        if (string.IsNullOrEmpty(value))
                        {
                            _logChannel = null;
                        }
                        else
                        {
                            _logChannel = TaskSchedulerHelper.ConnectToPipe(value);
                        }
                        break;
                    case "eh":
                        if (string.IsNullOrEmpty(value))
                        {
                            Console.WriteLine($"Missing event name in \"/eh\" option");
                            return false;
                        }
                        try
                        {
                            _waitEvent = EventWaitHandle.OpenExisting(value, EventWaitHandleRights.Modify);
                        }
                        catch
                        {
                            Console.WriteLine($"Invalid event name in \"/eh\" option");
                            return false;
                        }
                        break;
                    case "tu":
                        // Username can be empty, in edit it means we leave the current username
                        // It will be handled later when adding/editing the credential.
                        _targetUsername = value;
                        break;
                    case "tp":
                        // Password can be empty, so we don't check for null or empty here.
                        // It will be handled later when adding/editing the credential.
                        _targetPassword = GetPasswordSecure(value);
                        break;
                    case "e":
                        _actionType = ActionType.Edit;
                        _targetName = value;
                        if (string.IsNullOrEmpty(_targetName))
                        {
                            Console.WriteLine($"Missing value in \"/e\" option");
                            return false;
                        }
                        break;
                    case "a":
                        _actionType = ActionType.SearchAll;
                        break;
                    case "s":
                        _actionType = ActionType.Search;
                        _targetName = value;
                        if (string.IsNullOrEmpty(_targetName))
                        {
                            Console.WriteLine($"Missing value in \"/s\" option");
                            return false;
                        }
                        break;
                    case "d":
                        _actionType = ActionType.Delete;
                        _targetName = value;
                        if (string.IsNullOrEmpty(_targetName))
                        {
                            Console.WriteLine($"Missing value in \"/d\" option");
                            return false;
                        }
                        break;
                    case "p":
                        _actionType = ActionType.SearchAssembly;
                        break;
                    case "ls":
                        if (userType == UserType.DifferentUser)
                        {
                            Console.WriteLine($"Use only one option between /u and /ls");
                            return false;
                        }

                        if (!IsProcessElevated())
                        {
                            Console.WriteLine($"Impersonation requires elevated privileges. Please run the application as administrator.");
                            return false;
                        }

                        _impersonate = true;
                        userType = UserType.LocalSystem;
                        break;
                    case "sh":
                        _showPwd = true;
                        break;
                    case "u":
                        if (userType == UserType.LocalSystem)
                        {
                            Console.WriteLine($"Use only one option between /u and /ls");
                            return false;
                        }

                        _impersonateUser = value;
                        if (string.IsNullOrEmpty(_impersonateUser))
                        {
                            Console.WriteLine($"Missing value in \"/u\" option");
                            return false;
                        }

                        if (!IsProcessElevated())
                        {
                            Console.WriteLine($"Impersonation requires elevated privileges. Please run the application as administrator.");
                            return false;
                        }

                        _impersonate = true;
                        userType = UserType.DifferentUser;
                        break;
                    default:
                        Console.WriteLine($"Unknown option - \"/{action}\"");
                        return false;
                }
            }

            return true;
        }

        private static void GetConfiguration<T>() where T : class
        {
            configuration = new ConfigurationBuilder()
                .AddCredentialManager<T>()
                .Build();

            DumpCredentialKeys();
        }
        private static void GetConfiguration(string prefix)
        {
            configuration = new ConfigurationBuilder()
                .AddCredentialManager(prefix)
                .Build();

            DumpCredentialKeys();
        }

        private static void RemoveCredential(string targetName)
        {
            var existingCred = new Credential()
            {
                Target = targetName
            };

            try
            {
                if (!existingCred.Delete())
                {
                    Console.WriteLine($"Error deleting the credential with target '{existingCred.Target}'");
                }
                else
                {
                    Console.WriteLine($"Credential with target '{existingCred.Target}' deleted");
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine($"Error deleting credential with target name {targetName}: {exc.Message}");
            }
        }
        
        private static void AddCredential(Credential existingCredential = null)
        {
            if (_targetUsername == null)
            {
                Console.WriteLine($"Username is required to add a new credential");
                return;
            }

            if (existingCredential != null)
            {
                if (!string.IsNullOrEmpty(_targetUsername))
                {
                    existingCredential.Username = _targetUsername;
                }
                existingCredential.SecurePassword = _targetPassword;

                try
                {
                    if (!existingCredential.Save())
                    {
                        Console.WriteLine($"Error editing the credential with target name '{existingCredential.Target}'");
                    }
                    else
                    {
                        Console.WriteLine($"Credential with target name '{existingCredential.Target}' updated");
                    }
                }
                catch (Exception exc)
                {
                    Console.WriteLine($"Error editing the credential with target name '{existingCredential.Target}': {exc.Message}");
                }
            }
            else
            {
                try
                {
                    var newCred = new Credential(_targetUsername, _targetPassword, _targetName, CredentialType.Generic, PersistanceType.LocalComputer);
                    if (!newCred.Save())
                    {
                        Console.WriteLine($"Error adding the new credential");
                    }
                    else
                    {
                        Console.WriteLine($"New credential with target name '{newCred.Target}' added");
                    }
                }
                catch (Exception exc)
                {
                    Console.WriteLine($"Error adding the new credential with target name {_targetName}': {exc.Message}");
                }
            }
        }
        private static void EditCredential(string targetName)
        {
            var existingCred = new Credential()
            {
                Target = targetName
            };

            try
            {
                if (!existingCred.Load())
                {
                    Console.WriteLine($"Credential with target name '{targetName}' does not exists.");
                    return;
                }
                else
                {
                    Console.WriteLine($"Credential with target name '{targetName}' found, updating data.");
                    AddCredential(existingCred);
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine($"Error reading credential with target name '{targetName}': {exc.Message}");
            }
        }

        private static void GetTargetCredentials(bool bEdit)
        {
            // If the username is not provided, prompt for it.
            if (_targetUsername == null)
            {
                if (bEdit)
                {
                    Console.Write($"Username (leave empty to keep current): ");
                }
                else 
                {
                    Console.Write($"Username: ");
                }
                _targetUsername = Console.ReadLine();
            }

            // If the password is not provided, prompt for it.
            if (_targetPassword == null)
            {
                _targetPassword = ReadPasswordSecure("Password: ", false);
            }
        }

        private static void DumpCredentialKeys()
        {
            foreach (var config in configuration.AsEnumerable())
            {
                if (config.Key.EndsWith("Password") && !_showPwd)
                {
                    Console.WriteLine($"{config.Key}: ***");
                }
                else
                {
                    Console.WriteLine($"{config.Key}: {config.Value}");
                }
            }
        }

        private static SecureString ReadPasswordSecure(string message, bool withEcho)
        {
            var secure = new SecureString();
            
            if (message != null)
            {
                Console.Write(message);
            }

            try
            {
                ConsoleKey key;
                do
                {
                    var keyInfo = Console.ReadKey(intercept: true);
                    key = keyInfo.Key;

                    if (key == ConsoleKey.Backspace && secure.Length > 0)
                    {
                        if (withEcho)
                        {
                            Console.Write("\b \b");
                        }
                        secure.RemoveAt(secure.Length - 1);
                    }
                    else if (!char.IsControl(keyInfo.KeyChar))
                    {
                        if (withEcho)
                        {
                            Console.Write("*");
                        }
                        secure.AppendChar(keyInfo.KeyChar);
                    }
                } while (key != ConsoleKey.Enter);

                Console.WriteLine();

                secure.MakeReadOnly();
                return secure;
            }
            catch
            {
                secure.Dispose();
                throw;
            }
        }
        private static SecureString GetPasswordSecure(string password)
        {
            var secure = new SecureString();
            foreach (var c in password)
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }
        
        static bool IsProcessElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        static void WaitForDebugger(int timeoutSeconds)
        {
            //// scrivi il PID dove puoi leggerlo (log, Event Log, file in una cartella accessibile)
            //File.WriteAllText(Path.Combine(Path.GetTempPath(), "mioapp-debug.pid"),
            //                  Process.GetCurrentProcess().Id.ToString());

            Console.WriteLine($"Waiting for debugger {timeoutSeconds} seconds...");

            var sw = Stopwatch.StartNew();
            while (!Debugger.IsAttached && sw.Elapsed.TotalSeconds < timeoutSeconds)
            {
                Thread.Sleep(500);
            }

            if (Debugger.IsAttached)
            {
                Debugger.Break();
            }
        }
    }
}
