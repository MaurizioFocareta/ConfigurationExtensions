using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecretsManager
{
    internal class AppConstants
    {
        public static string AppSeed = "SecretsManager.v1.credentials";
        public static string ProgramDataAppPath = "HPE\\SecretsManager";
        public static string TaskManagerTask = "SecretsMamagerTask";

        public static string[] ActionParameters = new string[] { "?", "w", "e", "a", "s", "d", "p" };
        public static string[] OptionParameters = new string[] { "u", "ls", "tu", "tp", "bl", "eh", "pp", "sh" };

        public static string[] AllParameters = ActionParameters.Concat(OptionParameters).ToArray();
    }
}
