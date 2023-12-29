using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace HPE.Extensions.Configuration.CredentialManager
{
    /// <summary>
    /// Configuration extensions for adding Windows Credential Manager configuration source.
    /// </summary>
    public static class CredentialManagerConfigurationExtensions
    {
        public static IConfigurationBuilder AddCredentialManager<T>(this IConfigurationBuilder configuration)
            where T : class
            => configuration.AddCredentialManager(typeof(T).Assembly, optional: true);

        public static IConfigurationBuilder AddCredentialManager<T>(this IConfigurationBuilder configuration, bool optional)
            where T : class
            => configuration.AddCredentialManager(typeof(T).Assembly, optional);

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, Assembly assembly)
            => configuration.AddCredentialManager(assembly, optional: true);

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, Assembly assembly, bool optional)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            if (assembly == null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            CredentialManagerPrefixIdAttribute attribute = assembly.GetCustomAttribute<CredentialManagerPrefixIdAttribute>();
            if (attribute != null)
            {
                return AddCredentialManagerInternal(configuration, attribute.PrefixId);
            }

            if (!optional)
            {
                throw new InvalidOperationException($"Missing PrefixId attribute in assembly {assembly.GetName().Name}");
            }

            return configuration;
        }

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, string prefixId)
            => AddCredentialManagerInternal(configuration, prefixId);

        private static IConfigurationBuilder AddCredentialManagerInternal(IConfigurationBuilder configuration, string prefixId)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            if (prefixId == null)
            {
                throw new ArgumentNullException(nameof(prefixId));
            }

            return configuration.Add(new CredentialManagerConfigurationProvider(prefixId));
        }
    }
}
