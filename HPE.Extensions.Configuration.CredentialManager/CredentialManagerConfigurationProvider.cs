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

        public string PrefixTag { get; set; }

        public string UsernameTag { get; set; }
        public string PasswordTag { get; set; }

        public CredentialManagerConfigurationProvider()
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="prefixId">The prefix string to filter credentials in Credentials Manager</param>
        /// <param name="prefixTag">The tag that is prefixed to the Target name in credential store. If null the default "CustomCredentials" will be used. If empty no prefix tag will be added.</param>
        /// <param name="usernameTag">The tag that is postfixed to the Target for the Username field.</param>
        /// <param name="passwordTag">The tag that is postfixed to the Target for the Password field.</param>
        public CredentialManagerConfigurationProvider(string prefixId, CredentialManagerConfigurationOptions options) : this()
        {
            PrefixId = prefixId;
            PrefixTag = options.PrefixTag;
            UsernameTag = options.UsernameTag;
            PasswordTag = options.PasswordTag;
        }

        public override void Load()
        {
            CredentialSet credentials = new CredentialSet(PrefixId);

            credentials.Load();

            foreach (var credential in credentials.Where(c => c.Type == CredentialType.Generic))
            {
                var keyName = string.Empty;
                if (PrefixTag != string.Empty)
                {
                    keyName = $"{PrefixTag}:";
                }
                keyName += $"{credential.Target}";

                var usernameKey = $"{keyName}:{UsernameTag}";
                if (Data.ContainsKey(usernameKey))
                {
                    Data[usernameKey] = credential.Username;
                }
                else
                {
                    Data.Add(usernameKey, credential.Username);
                }

                var passwordKey = $"{keyName}:{PasswordTag}";
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
