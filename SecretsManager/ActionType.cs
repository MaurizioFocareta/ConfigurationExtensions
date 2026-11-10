using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecretsManager
{
    internal static class ActionTypeExtensions
    {
        public static string GetActionString(this ActionType value)
        {
            var field = typeof(ActionType).GetField(value.ToString());
            var attr = field?.GetCustomAttribute<ActionStringAttribute>();
            return attr?.Name;
        }
    }

    internal class ActionStringAttribute : Attribute
    {
        public string Name { get; set; }

        public ActionStringAttribute(string name) { Name = name; }
    }

    internal enum ActionType
    {
        None,
        [ActionString("?")]
        ShowHelp,
        [ActionString("s")]
        Search,
        [ActionString("a")]
        SearchAll,
        [ActionString("p")]
        SearchAssembly,
        [ActionString("w")]
        Add,
        [ActionString("e")]
        Edit,
        [ActionString("d")]
        Delete
    }
}
