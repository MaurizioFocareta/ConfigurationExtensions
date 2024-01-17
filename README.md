# Configuration extensions

This is a set libraries to extend Microsoft.Extensions.Configuration with some custom providers (Legacy and CredentialManager).

# Legacy

Custom Configuration Provider to read key/values from legacy xml configuration files (app.config, web.config) and integrate them in the Microsoft.Extensions.Configuration library.

The ConnectionStrings section is mapped to keys with "ConnectionString:[Name]" format.

The AppSettings section is directly mapped to configuration keys.

# CredentialManager

C# wrapper for CredRead function to retreive secrets from Windows Credential Store and integrate them in the Microsoft.Extensions.Configuration library.

It's based on work from https://github.com/ilyalozovyy/credentialmanagement and adapted to work with Configuration framework.

The credentials are mapped to keys with "CustomCredentials:[TargetName]:Username" and "CustomCredentials:[TargetName]:Password" format.

# SecretsManager

A simple console application to get/add/delete credentials from the Windows Credential Store. 

The tool manages "Generic" CredentialType credentials in the store of the current user.

To manage credentials for LocalSystem account execute the tool with: psexec -i -s.