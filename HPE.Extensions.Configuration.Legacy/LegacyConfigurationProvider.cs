using Microsoft.Extensions.Configuration;

namespace HPE.Extensions.Configuration.Legacy
{
    public class LegacyConfigurationProvider : ConfigurationProvider, IConfigurationSource
    {
        private readonly System.Configuration.Configuration _configuration;

        public LegacyConfigurationProvider(string path)
        {
            if (path == null)
            {
                _configuration = System.Configuration.ConfigurationManager.OpenExeConfiguration(System.Configuration.ConfigurationUserLevel.None);
            }
            else
            {
                var fileMap = new System.Configuration.ExeConfigurationFileMap { ExeConfigFilename = path };
                _configuration = System.Configuration.ConfigurationManager.OpenMappedExeConfiguration(fileMap, System.Configuration.ConfigurationUserLevel.None);
            }
        }

        public override void Load()
        {
            foreach (System.Configuration.ConnectionStringSettings connectionString in _configuration.ConnectionStrings.ConnectionStrings)
            {
                Data.Add($"ConnectionStrings:{connectionString.Name}", connectionString.ConnectionString);
            }

            foreach (var settingKey in _configuration.AppSettings.Settings.AllKeys)
            {
                Data.Add(settingKey, _configuration.AppSettings.Settings[settingKey].Value);
            }
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return this;
        }
    }
}
