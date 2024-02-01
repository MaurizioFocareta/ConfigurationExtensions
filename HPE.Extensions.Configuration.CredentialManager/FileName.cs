using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HPE.Extensions.Configuration.CredentialManager
{
    public class CredentialManagerConfigurationOptions
    {
        public string PrefixTag { get; set; } = "CustomCredentials";
        public string UsernameTag { get; set; } = "Username";
        public string PasswordTag { get; set; } = "Password";
    }
}
