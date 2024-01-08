using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;

namespace SecretsManager
{
    internal class Program
    {
        private static IConfigurationRoot configuration;

        private static void HelpString()
        {
            Console.WriteLine("Secrets Manager in Windows CredentialManager (HPE 2023)");
            Console.WriteLine();
            Console.WriteLine("SecretsManager [-w] [-a] [-p] [-s <Filter>] [-d <Target>]");
            Console.WriteLine();
            Console.WriteLine("-w\t\tAdd new generic credential for the current user");
            Console.WriteLine("-a\t\tGet all generic credential keys for the current user");
            Console.WriteLine("-p\t\tGet all generic credential keys for the current user with Target based on assembly attribute");
            Console.WriteLine("\t\tThe assembly is searched for the CredentialManagerPrefixId attribute");
            Console.WriteLine("-s <Filter>\tGet all generic credential keys for the current user with Target starting with <Filter>");
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
                Console.WriteLine(config.Key);
            }
        }

        private static void RemoveCredential(string targetName)
        {
            var newCred = new Credential()
            {
                Target = targetName
            };

            newCred.Delete();
        }

        private static void AddCredential()
        {
            Console.Write("TargetName: ");
            var targetName = Console.ReadLine();
            Console.Write("Username: ");
            var username = Console.ReadLine();
            Console.Write("Password: ");
            var password = ReadPassword(false);

            var newCred = new Credential(username, password, targetName, CredentialType.Generic, PersistanceType.LocalComputer);
            newCred.Save();
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
