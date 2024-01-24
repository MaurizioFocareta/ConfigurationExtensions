using HPE.Extensions.Configuration.Legacy;
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
    public static class LegacyConfigurationExtentions
    {
        public static IConfigurationBuilder AddLegacy(this IConfigurationBuilder configuration)
            => AddLegacy(configuration, configPath: null);

        public static IConfigurationBuilder AddLegacy(this IConfigurationBuilder configuration, System.Configuration.Configuration legacyConfiguration)
            => AddLegacyInternal(configuration, legacyConfiguration);

        public static IConfigurationBuilder AddLegacy(this IConfigurationBuilder configuration, string configPath)
            => AddLegacyInternal(configuration, configPath);

        private static IConfigurationBuilder AddLegacyInternal(IConfigurationBuilder configuration, string configPath)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            return configuration.Add(new LegacyConfigurationProvider(configPath));
        }
        private static IConfigurationBuilder AddLegacyInternal(IConfigurationBuilder configuration, System.Configuration.Configuration legacyConfiguration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            return configuration.Add(new LegacyConfigurationProvider(legacyConfiguration));
        }
    }
}
