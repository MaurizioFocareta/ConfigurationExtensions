using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace SecretsManager
{
    internal class Program
    {
        private static IConfigurationRoot configuration;

        private static ActionType _actionType = ActionType.None;
        private static UserType userType = UserType.CurrentUser;

        private static bool _showPasswords = false;
        private static string _searchValue = null;
        
        private static bool _impersonate = false;

        private static string _impersonateUser = null;
        private static SecureString _impersonatePassword = null;

        private static void ShowHelp()
        {
            Console.WriteLine("Secrets Manager in Windows CredentialManager (HPE 2024)");
            Console.WriteLine($"Build: {Assembly.GetExecutingAssembly().GetName().Version}");
            Console.WriteLine();
            Console.WriteLine("SecretsManager [/u:user | /ls] [/w | /e:<Target> | /a | /s:<Filter> | /d:<Target> | /p]");
            Console.WriteLine();
            Console.WriteLine("User impersonation context:");
            Console.WriteLine("/u\t\tThe action is performed in the context of the given user. Mutually exclusive with /ls.");
            Console.WriteLine("\t\t(You will be prompted for the password. This option requires elevated privileges).");
            Console.WriteLine("/ls\t\tThe action is performed in the context of local system account. Mutually exclusive with /u.");
            Console.WriteLine("\t\t(This option requires elevated privileges)");
            Console.WriteLine();
            Console.WriteLine("\t\tIf /u or /ls is not specified, the action is performed in the context of the current user.");
            Console.WriteLine("Actions:");
            Console.WriteLine("/w\t\tAdd new generic credentials.");
            Console.WriteLine("/e:<Target>\tEdit generic credentials with the given <Target>.");
            Console.WriteLine("/a\t\tGet all generic credentials.");
            Console.WriteLine("/s:<Filter>\tGet all generic credentials with Target starting with <Filter>.");
            Console.WriteLine("/d:<Target>\tRemoves the generic credentials with the given <Target>.");
            Console.WriteLine("/p\t\tGet all generic credentials with Target based on assembly attribute.");
            Console.WriteLine("\t\t(The assembly is searched for the CredentialManagerPrefixId attribute).");
            Console.WriteLine("Flags:");
            Console.WriteLine("/sh\t\tShow secret passwords for /a and /s actions. Ignored for other actions.");
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
            }
            else
            {
                if (ParseParameters(args))
                {
                    Action action = null;
                    switch (_actionType)
                    {
                        case ActionType.ShowHelp:
                            ShowHelp();
                            break;
                        case ActionType.Search:
                            action = new Action(() => GetConfiguration(_searchValue));
                            break;
                        case ActionType.SearchAll:
                            action = new Action(() => GetConfiguration(string.Empty));
                            break;
                        case ActionType.SearchAssembly:
                            action = new Action(() => GetConfiguration<Program>());
                            break;
                        case ActionType.Add:
                            action = new Action(() => AddCredential());
                            break;
                        case ActionType.Edit:
                            action = new Action(() => EditCredential(_searchValue));
                            break;
                        case ActionType.Delete:
                            action = new Action(() => RemoveCredential(_searchValue));
                            break;
                        default:
                            Console.WriteLine($"Select an action. Use /? or no argument for the help.");
                            break;
                    }

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
                                    ImpersonationHelper.RunAs(domain, user, _impersonatePassword, action);
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
            }
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

                if (_actionType != ActionType.None)
                {
                    if (action != "sh")
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
                        break;
                    case "e":
                        _actionType = ActionType.Edit;
                        _searchValue = value;
                        if (string.IsNullOrEmpty(_searchValue))
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
                        _searchValue = value;
                        if (string.IsNullOrEmpty(_searchValue))
                        {
                            Console.WriteLine($"Missing value in \"/s\" option");
                            return false;
                        }
                        break;
                    case "d":
                        _actionType = ActionType.Delete;
                        _searchValue = value;
                        if (string.IsNullOrEmpty(_searchValue))
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
                        _showPasswords = true;
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

                        _impersonatePassword = ReadPasswordSecure($"Password for user {_impersonateUser}: ", true);

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
            if (existingCredential != null)
            {
                Console.WriteLine($"TargetName: {existingCredential.Target}");
                Console.Write($"Username (current: {existingCredential.Username}): ");
                var username = Console.ReadLine();
                if (username != null)
                {
                    if (username == string.Empty)
                    {
                        username = existingCredential.Username;
                    }

                    var password = ReadPassword("Password: ", false);
                    if (string.IsNullOrEmpty(password))
                    {
                        password = existingCredential.Password;
                    }

                    existingCredential.Username = username;
                    existingCredential.Password = password;

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
            }
            else
            {
                Console.Write("TargetName: ");
                var targetName = Console.ReadLine();

                if (string.IsNullOrEmpty(targetName))
                {
                    Console.WriteLine($"Target name cannot be empty!");
                    return;
                }

                Console.Write("Username: ");
                var username = Console.ReadLine();
                if (username != null)
                {
                    var password = ReadPassword("Password: ", false);

                    try
                    {
                        var newCred = new Credential(username, password, targetName, CredentialType.Generic, PersistanceType.LocalComputer);
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
                        Console.WriteLine($"Error adding the new credential with target name {targetName}': {exc.Message}");
                    }
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
                    AddCredential(existingCred);
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine($"Error reading credential with target name '{targetName}': {exc.Message}");
            }
        }

        private static void DumpCredentialKeys()
        {
            foreach (var config in configuration.AsEnumerable())
            {
                if (!string.IsNullOrEmpty(config.Value))
                {
                    if (config.Key.EndsWith("Password") && !_showPasswords)
                    {
                        Console.WriteLine($"{config.Key}: ***");
                    }
                    else
                    {
                        Console.WriteLine($"{config.Key}: {config.Value}");
                    }
                }
                else
                {
                    Console.WriteLine(config.Key);
                }
            }
        }

        private static string ReadPassword(string message, bool withEcho)
        {
            string password = string.Empty;

            if (message != null)
            {
                Console.Write(message);
            }

            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && password.Length > 0)
                {
                    if (withEcho)
                    {
                        Console.Write("\b \b");
                    }
                    password = password.Remove(password.Length - 1);
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    if (withEcho)
                    {
                        Console.Write("*");
                    }
                    password += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            Console.WriteLine();

            return password;
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

        static bool IsProcessElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
