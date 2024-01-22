using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Linq.Expressions;

namespace SecretsManager
{
    internal class Program
    {
        private static IConfigurationRoot configuration;

        private static void HelpString()
        {
            Console.WriteLine("Secrets Manager in Windows CredentialManager (HPE 2024)");
            Console.WriteLine();
            Console.WriteLine("SecretsManager [-w] [-a] [-p] [-s <Filter>] [-d <Target>]");
            Console.WriteLine();
            Console.WriteLine("-w\t\tAdd new generic credentials for the current user");
            Console.WriteLine("-e <Target>\tEdit generic credentials for the current user with the given <Target>");
            Console.WriteLine("-a\t\tGet all generic credentials for the current user");
            Console.WriteLine("-p\t\tGet all generic credentials for the current user with Target based on assembly attribute");
            Console.WriteLine("\t\t(The assembly is searched for the CredentialManagerPrefixId attribute)");
            Console.WriteLine("-s <Filter>\tGet all generic credentials for the current user with Target starting with <Filter>");
            Console.WriteLine("-d <Target>\tRemoves the generic credentials for the current user with the given <Target>");
            Console.WriteLine();
        }

        static void Main(string[] args)
        {
            if (args.Length == 1)
            {
                if (args[0] == "-w")
                {
                    AddCredential();
                }
                else if (args[0] == "-a")
                {
                    GetConfiguration(string.Empty);
                }
                else if (args[0] == "-p")
                {
                    GetConfiguration<Program>();
                }
                else
                {
                    Console.WriteLine($"Unknown parameter {args[0]}");
                    HelpString();
                }
            }
            else if (args.Length == 2)
            {
                if (args[0] == "-s")
                {
                    GetConfiguration(args[1]);
                }
                else if (args[0] == "-d")
                {
                    RemoveCredential(args[1]);
                }
                else if (args[0] == "-e")
                {
                    EditCredential(args[1]);
                }
                else
                {
                    Console.WriteLine($"Unknown parameter {args[0]}");
                    HelpString();
                }
            }
            else
            {
                HelpString();
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
