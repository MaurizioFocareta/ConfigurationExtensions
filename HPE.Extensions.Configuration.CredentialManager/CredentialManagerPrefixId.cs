using System;

namespace HPE.Extensions.Configuration.CredentialManager
{
    /// <summary>
    /// <para>
    /// Represents prefix in Credential Manager entries target field.
    /// </para>
    /// </summary>
    [AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
    public class CredentialManagerPrefixIdAttribute : Attribute
    {
        /// <summary>
        /// Initializes an instance of <see cref="CredentialManagerPrefixId" />.
        /// </summary>
        /// <param name="prefixId">The prefix in Credential Manager entries target field.</param>
        public CredentialManagerPrefixIdAttribute(string prefixId)
        {
            if (string.IsNullOrEmpty(prefixId))
            {
                throw new ArgumentException("Argument cannot be null or empty", nameof(prefixId));
            }

            PrefixId = prefixId;
        }

        /// <summary>
        /// The prefix in Credential Manager entries target field
        /// </summary>
        public string PrefixId { get; }
    }
}
