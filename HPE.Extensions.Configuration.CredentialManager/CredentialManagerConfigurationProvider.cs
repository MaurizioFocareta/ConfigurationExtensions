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
            if (string.IsNullOrEmpty(prefixId))
            {
                throw new ArgumentNullException(nameof(prefixId));
            }

            PrefixId = prefixId;
        }

        public override void Load()
        {
            CredentialSet credentials = new CredentialSet(PrefixId);

            credentials.Load();

            foreach (var credential in credentials)
            {
                Data.Add($"CustomCredentials:{credential.Target.Remove(0, PrefixId.Length)}:Username", credential.Username);
                Data.Add($"CustomCredentials:{credential.Target.Remove(0, PrefixId.Length)}:Password", credential.Password);
            }
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return this;
        }
    }
}
