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
            var configuration = new ConfigurationBuilder()
                .AddCredentialManager<Program>()
                .Build();

            Console.WriteLine(configuration);
        }
    }
}
