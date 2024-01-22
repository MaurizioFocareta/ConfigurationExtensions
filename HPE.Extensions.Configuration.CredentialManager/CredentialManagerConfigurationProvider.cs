using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HPE.Extensions.Configuration.CredentialManager
{
    public class CredentialManagerConfigurationProvider : ConfigurationProvider, IConfigurationSource
    {
        public string PrefixId { get; set; }

        public CredentialManagerConfigurationProvider()
        {
        }

        public CredentialManagerConfigurationProvider(string prefixId) : this()
        {
            PrefixId = prefixId;
        }

        public override void Load()
        {
            CredentialSet credentials = new CredentialSet(PrefixId);

            credentials.Load();

            foreach (var credential in credentials.Where(c => c.Type == CredentialType.Generic))
            {
                var usernameKey = $"CustomCredentials:{credential.Target}:Username";
                if (Data.ContainsKey(usernameKey))
                {
                    Data[usernameKey] = credential.Username;
                }
                else
                {
                    Data.Add(usernameKey, credential.Username);
                }

                var passwordKey = $"CustomCredentials:{credential.Target}:Password";
                if (Data.ContainsKey(passwordKey))
                {
                    Data[passwordKey] = credential.Password;
                }
                else
                {
                    Data.Add(passwordKey, credential.Password);
                }
            }
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return this;
        }
    }
}
