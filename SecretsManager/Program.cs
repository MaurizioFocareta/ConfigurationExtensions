using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Linq.Expressions;
using System.Text.RegularExpressions;

namespace SecretsManager
{
    internal class Program
    {
        private static IConfigurationRoot configuration;

        private static ActionType _actionType = ActionType.None;
        private static string _searchValue = null;
        
        private static bool _impersonate = false;
        private static string _impersonateUser = null;

        private static void ShowHelp()
        {
            Console.WriteLine("Secrets Manager in Windows CredentialManager (HPE 2024)");
            Console.WriteLine();
            Console.WriteLine("SecretsManager /u:user [[/w]|[/e:<Target>]|[/a]|[/s:<Filter>]|[/d:<Target>][/p]");
            Console.WriteLine();
            Console.WriteLine("/w\t\tAdd new generic credentials for the current user");
            Console.WriteLine("/e:<Target>\tEdit generic credentials for the current user with the given <Target>");
            Console.WriteLine("/a\t\tGet all generic credentials for the current user");
            Console.WriteLine("/s:<Filter>\tGet all generic credentials for the current user with Target starting with <Filter>");
            Console.WriteLine("/d:<Target>\tRemoves the generic credentials for the current user with the given <Target>");
            Console.WriteLine("/p\t\tGet all generic credentials for the current user with Target based on assembly attribute");
            Console.WriteLine("\t\t(The assembly is searched for the CredentialManagerPrefixId attribute)");
            Console.WriteLine();
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
                    switch (_actionType)
                    {
                        case ActionType.ShowHelp:
                            ShowHelp();
                            break;
                        case ActionType.Search:
                            GetConfiguration(_searchValue);
                            break;
                        case ActionType.SearchAll:
                            GetConfiguration(string.Empty);
                            break;
                        case ActionType.SearchAssembly:
                            GetConfiguration<Program>();
                            break;
                        case ActionType.Add:
                            AddCredential();
                            break;
                        case ActionType.Edit:
                            EditCredential(_searchValue);
                            break;
                        case ActionType.Delete:
                            RemoveCredential(_searchValue);
                            break;
                        default:
                            Console.WriteLine($"Select an action. Use /h or no argument for the help.");
                            break;
                    }
                }
            }
        }

        static bool ParseParameters(string[] args)
        {
            foreach (var arg in args)
            {
                Regex argRegEx = new Regex("/(?<Switch>\\w):?(?<Value>.*)?");
                var match = argRegEx.Match(arg);
                if (!match.Success)
                {
                    Console.WriteLine($"Invalid option - \"{arg}\"");
                    return false;
                }

                if (_actionType != ActionType.None)
                {
                    Console.WriteLine($"Use only one option between /w /e /a /s /d /p");
                    return false;
                }

                var action = match.Groups["Switch"].Value;
                var value = match.Groups["Value"].Value;

                switch (action)
                {
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
                    case "u":
                        _impersonate = true;
                        _impersonateUser = value;
                        if (string.IsNullOrEmpty(_impersonateUser))
                        {
                            Console.WriteLine($"Missing value in \"/u\" option");
                            return false;
                        }
                        break;
                    default:
                        Console.WriteLine($"Unknown option - \"/{action}\"");
                        return false;
                }
            }

            return true;
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

        private static void DumpCredentialKeys()
        {
            foreach (var config in configuration.AsEnumerable())
            {
                if (!string.IsNullOrEmpty(config.Value))
                {
                    if (config.Key.EndsWith("Password"))
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
                    Console.Write("Password: ");
                    var password = ReadPassword(false);
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
                    Console.Write("Password: ");
                    var password = ReadPassword(false);

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

        private static string ReadPassword(bool withEcho)
        {
            string password = string.Empty;

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
    }
}
