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
                var connectionStringKey = $"ConnectionStrings:{connectionString.Name}";
                if (Data.ContainsKey(connectionStringKey))
                {
                    Data[connectionStringKey] = connectionString.ConnectionString;
                }
                else
                {
                    Data.Add(connectionStringKey, connectionString.ConnectionString);
                }
            }

            foreach (var settingKey in _configuration.AppSettings.Settings.AllKeys)
            {
                if (Data.ContainsKey(settingKey))
                {
                    Data[settingKey] = _configuration.AppSettings.Settings[settingKey].Value;
                }
                else
                {
                    Data.Add(settingKey, _configuration.AppSettings.Settings[settingKey].Value);
                }
            }
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return this;
        }
    }
}
