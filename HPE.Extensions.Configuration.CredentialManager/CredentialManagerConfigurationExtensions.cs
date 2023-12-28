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
            => configuration.AddCredentialManager(typeof(T).Assembly, optional: true, reloadOnChange: false);

        public static IConfigurationBuilder AddCredentialManager<T>(this IConfigurationBuilder configuration, bool optional)
            where T : class
            => configuration.AddCredentialManager(typeof(T).Assembly, optional, reloadOnChange: false);

        public static IConfigurationBuilder AddCredentialManager<T>(this IConfigurationBuilder configuration, bool optional, bool reloadOnChange)
            where T : class
            => configuration.AddCredentialManager(typeof(T).Assembly, optional, reloadOnChange);

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, Assembly assembly)
            => configuration.AddCredentialManager(assembly, optional: true, reloadOnChange: false);

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, Assembly assembly, bool optional)
            => configuration.AddCredentialManager(assembly, optional, reloadOnChange: false);

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, Assembly assembly, bool optional, bool reloadOnChange)
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
                return AddCredentialManagerInternal(configuration, attribute.PrefixId, optional, reloadOnChange);
            }

            if (!optional)
            {
                throw new InvalidOperationException($"Missing PrefixId attribute in assembly {assembly.GetName().Name}");
            }

            return configuration;
        }

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, string prefixId)
            => configuration.AddCredentialManager(prefixId, reloadOnChange: false);

        public static IConfigurationBuilder AddCredentialManager(this IConfigurationBuilder configuration, string prefixId, bool reloadOnChange)
            => AddCredentialManagerInternal(configuration, prefixId, true, reloadOnChange);

        private static IConfigurationBuilder AddCredentialManagerInternal(IConfigurationBuilder configuration, string prefixId, bool optional, bool reloadOnChange)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            if (prefixId == null)
            {
                throw new ArgumentNullException(nameof(prefixId));
            }

            return configuration.Add(new CredentialManagerConfigurationProvider());
        }
    }
}
