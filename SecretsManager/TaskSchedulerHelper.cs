using HPE.Extensions.Configuration.CredentialManager;
using Microsoft.Win32.TaskScheduler;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.Remoting.Messaging;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SecretsManager
{
    internal class TaskSchedulerHelper
    {
        static string WriteTempBlob(byte[] blob, string smsaAccount, string dir)
        {
            SecurityIdentifier smsa;
            try
            {
                smsa = (SecurityIdentifier)new NTAccount(smsaAccount).Translate(typeof(SecurityIdentifier));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unable to translate managed service account {smsaAccount}: {ex.Message}");
                return null;
            }

            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            try
            {
                var sec = new FileSecurity();
                sec.SetAccessRuleProtection(true, false);
                sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(smsa, FileSystemRights.Read | FileSystemRights.Delete, AccessControlType.Allow));

                Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");

                using (var fs = new FileStream(path, FileMode.CreateNew,
                    FileSystemRights.WriteData | FileSystemRights.ReadAttributes,
                    FileShare.None, 4096, FileOptions.None, sec))
                {
                    fs.Write(blob, 0, blob.Length);
                }

                return path;
            }
            catch (Exception exc)
            {
                Console.WriteLine($"Unable to store credentials blob: {exc.Message}");
                return null;
            }
        }

        public static Credential ImportFromTempBlob(string blobPath)
        {
            try
            {
                var blob = File.ReadAllBytes(blobPath);
                return SecretStore.Unprotect(blob, DataProtectionScope.LocalMachine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"There was a problem getting credentials from blob file: {ex.Message}");
                return null;
            }
            finally
            {
                try { File.Delete(blobPath); } catch { }
            }
        }

        public sealed class NamedEvent : IDisposable
        {
            public string Name { get; private set; }
            public EventWaitHandle Handle { get; private set; }

            public NamedEvent(string name, EventWaitHandle handle)
            {
                Name = name;
                Handle = handle;
            }

            public void Dispose() { Handle.Dispose(); }
        }
        public sealed class NamedPipe : IDisposable
        {
            public string Name { get; private set; }
            public System.Threading.Tasks.Task Reader { get; set; }

            public NamedPipeServerStream Server { get; set; }
            public CancellationTokenSource Cts { get; set; }

            public NamedPipe(string name)
            {
                Name = name;
            }

            public override string ToString()
            {
                return Name;
            }

            public void Dispose()
            {
                Cts?.Dispose();
            }
        }

        public static NamedEvent CreateWaitHandle(string domain, string user)
        {
            var eventName = $"Global\\{AppConstants.AppSeed}.{Guid.NewGuid():N}";

            var smsa = (SecurityIdentifier)new NTAccount($"{domain}\\{user}").Translate(typeof(SecurityIdentifier));

            var evSec = new EventWaitHandleSecurity();
            evSec.AddAccessRule(new EventWaitHandleAccessRule(smsa,
                EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize,
                AccessControlType.Allow));

            var retValue = new NamedEvent(eventName, new EventWaitHandle(false, EventResetMode.ManualReset, eventName, out bool created, evSec));
            
            if (!created)
            {
                throw new InvalidOperationException("Nome evento già in uso");
            }

            return retValue;
        }

        public static NamedPipe CreateNamedPipe(string domain, string user)
        {
            var pipeName = $"{AppConstants.AppSeed}.{Guid.NewGuid():N}";

            var namedPipe = new NamedPipe(pipeName);

            try
            {
                var smsa = (SecurityIdentifier)new NTAccount($"{domain}\\{user}").Translate(typeof(SecurityIdentifier));

                var ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,
                    PipeAccessRights.FullControl, AccessControlType.Allow));
                ps.AddAccessRule(new PipeAccessRule(smsa,
                    PipeAccessRights.ReadWrite, AccessControlType.Allow));

                namedPipe.Cts = new CancellationTokenSource();
                namedPipe.Server = new NamedPipeServerStream(pipeName, PipeDirection.In, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, ps);

                namedPipe.Reader = System.Threading.Tasks.Task.Run(() =>
                {
                    try
                    {
                        namedPipe.Server.WaitForConnectionAsync(namedPipe.Cts.Token).Wait();
                        using (var sr = new StreamReader(namedPipe.Server, new UTF8Encoding(false)))
                        {
                            string line;
                            while ((line = sr.ReadLine()) != null)
                            {
                                Console.WriteLine("[Task] " + line);
                            }
                        }
                    }
                    catch (Exception) { /* cancelled, or the child never connected */ }
                });
            }
            catch 
            {
                Console.WriteLine("Can't create named pipe, child process logs will not show.");
                return null;
            }

            return namedPipe;
        }

        public static void SignalWaitEvent(EventWaitHandle waitEvent)
        {
            if (waitEvent != null)
            {
                try
                {
                    waitEvent.Set();
                }
                finally
                {
                    waitEvent.Dispose();
                }
            }
        }

        public static void CloseNamedPipe(StreamWriter pipeChannel)
        {
            if (pipeChannel != null)
            {
                try
                {
                    pipeChannel.Dispose();
                }
                catch { }
            }
        }

        public static StreamWriter ConnectToPipe(string pipeName)
        {
            if (pipeName == null) return null;
            try
            {
                var client = new NamedPipeClientStream(".", pipeName, PipeDirection.Out);
                client.Connect(3000);
                var w = new StreamWriter(client, new UTF8Encoding(false)) { AutoFlush = true };
                var sync = TextWriter.Synchronized(w);
                Console.SetOut(sync);
                Console.SetError(sync);
                return w;
            }
            catch
            {
                return null;
            }
        }

        public static void RunaAsManagedServiceAccount(string domain, string user, ActionType action, string targetName, string targetUsername, SecureString targetPassword, bool showPwd)
        {
            var currentProcessPath = Process.GetCurrentProcess().MainModule.FileName;
            
            var sMSA = $"{domain}\\{user}";

            // string taskArguments = "--attach ";
            string taskArguments = null;

            switch (action)
            {
                case ActionType.None:
                case ActionType.ShowHelp:
                    break;
                case ActionType.Delete:
                case ActionType.Search:
                    taskArguments += $"/{action.GetActionString()}:{targetName}";
                    if (showPwd)
                    {
                        taskArguments += " /sh";
                    }
                    break;
                case ActionType.SearchAll:
                case ActionType.SearchAssembly:
                    taskArguments += $"/{action.GetActionString()}";
                    if (showPwd)
                    {
                        taskArguments += " /sh";
                    }
                    break;
                case ActionType.Add:
                case ActionType.Edit:
                    var blobPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), $"{AppConstants.ProgramDataAppPath}\\provisioning");
                    var blobCredential = SecretStore.Protect(new Credential(targetUsername, targetPassword), DataProtectionScope.LocalMachine);
                    var temporaryBlobPath = WriteTempBlob(blobCredential, sMSA, blobPath);
                    taskArguments += $"/{action.GetActionString()}:{targetName} /bl:\"{temporaryBlobPath}\"";
                    break;
                default:
                    break;
            }

            if (!string.IsNullOrEmpty(taskArguments))
            {
                using (var ts = new TaskService())
                using (var waitEvent = CreateWaitHandle(domain, user))
                using (var namedPipe = CreateNamedPipe(domain, user))
                {
                    try
                    {
                        taskArguments += $" /eh:{waitEvent.Name}";

                        if (!string.IsNullOrEmpty(namedPipe?.Name))
                        {
                            taskArguments += $" /pp:{namedPipe.Name}";
                        }

                        var td = ts.NewTask();
                        td.Principal.UserId = sMSA;
                        // No password is needed for MSA, but we need to set the logon type to Password
                        // to avoid "The task is configured with an unsupported combination of account
                        // settings and run time settings" error.
                        td.Principal.LogonType = TaskLogonType.Password;
                        td.Actions.Add(new ExecAction(currentProcessPath, taskArguments, null));

                        ts.RootFolder.RegisterTaskDefinition(
                            AppConstants.TaskManagerTask, td, TaskCreation.CreateOrUpdate,
                            sMSA, null, TaskLogonType.Password);

                        var task = ts.FindTask(AppConstants.TaskManagerTask);
                        task.Run();

                        // blocca qui finché il figlio segnala
                        bool signaled = waitEvent.Handle.WaitOne(TimeSpan.FromSeconds(60));

                        // Only now drain the pipe, with a short timeout
                        if (!namedPipe.Reader.Wait(TimeSpan.FromSeconds(5)))
                        {
                            namedPipe.Cts.Cancel();
                        }

                        if (signaled)
                        {
                            // il processo sta uscendo: attendi che il task non risulti più Running e poi leggi l'esito
                            var sw = Stopwatch.StartNew();
                            do
                            {
                                Thread.Sleep(100);
                                task = ts.FindTask(AppConstants.TaskManagerTask);
                            }
                            while (task != null && task.State == TaskState.Running && sw.Elapsed < TimeSpan.FromSeconds(10));
                            int exitCode = task != null ? task.LastTaskResult : -1; // 0 = ok

                            if (exitCode == 0)
                            {
                                Console.WriteLine($"Managed service account task completed successfully");
                            }
                            else
                            {
                                Console.WriteLine($"Managed service account task failed");
                            }
                        }
                        else
                        {
                            // timeout: il task non è partito o il figlio è morto prima di segnalare
                            var t = ts.FindTask(AppConstants.TaskManagerTask);
                            if (t != null)
                            {
                                // TODO
                                // controlla task.LastTaskResult / task.LastRunTime per la diagnosi
                                Console.WriteLine($"Managed service account task did not complete successfully. Task result: {task.LastTaskResult}");
                            }
                        }
                    }
                    finally
                    {
                        var t = ts.FindTask(AppConstants.TaskManagerTask);
                        if (t != null)
                        {
                            try
                            {
                                ts.RootFolder.DeleteTask(AppConstants.TaskManagerTask, false);
                            }
                            catch
                            {
                                Console.WriteLine($"Managed service account task {AppConstants.TaskManagerTask} was not deleted successfully. Manually delete it from the system.");
                            }
                        }
                    }
                }
            }
        }
    }
}
