using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            IConfigurationRoot configuration;

            if (args.Length == 1)
            {
                if (args[0] == "-w")
                {
                    AddCredential();
                    return;
                }
                else if (args[0] == "-a")
                {
                    configuration = new ConfigurationBuilder()
                        .AddCredentialManager(string.Empty)
                        .Build();
                }
                else
                {
                    Console.WriteLine($"Unknown parameter {args[0]}");
                    return;
                }
            }
            else if (args.Length == 2)
            {
                if (args[0] == "-s")
                {
                    configuration = new ConfigurationBuilder()
                        .AddCredentialManager(args[1])
                        .Build();
                }
                else if (args[0] == "-d")
                {
                    RemoveCredential(args[1]);
                    return;
                }
                else
                {
                    Console.WriteLine($"Unknown parameter {args[0]}");
                    return;
                }
            }
            else
            {
                configuration = new ConfigurationBuilder()
                    .AddCredentialManager<Program>()
                    .Build();
            }

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
