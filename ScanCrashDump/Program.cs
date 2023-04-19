using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ScanCrashDump
{
    public static class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(@"Please enter the location to the *.dmp file: (e.g. C:\dbg\dumps\k2hostserver.dmp)");

            string dumpFile = Console.ReadLine();

            //string dumpFile = @"s:\Dumps-89246\k2hostserver.dmp";

            if ((args.Length > 0) && (File.Exists(args[0])))
            {
                dumpFile = args[0];
            }

            WriteMessage(string.Format("Loadling crashdump: {0}", dumpFile));


            using (var dt = DataTarget.LoadCrashDump(dumpFile))
            {
                //c:\\Users\\THINUS~1.K2W\\AppData\\Local\Temp\symbols 
                dt.AppendSymbolPath(@"C:\dbg\symbols");
                dt.AppendSymbolPath(@"SRV*http://msdl.microsoft.com/download/symbols");
                
                string dacLocation = dt.ClrVersions[0].TryGetDacLocation();
                //if (string.IsNullOrEmpty(dacLocation))
                //{
                ////    dacLocation = @"C:\dbg\symbols";
                //    dacloc = DacLocator.FromPublicSymbolServer(localCachePathTextBox.Text);
                //    String dac = dacloc.FindDac(dt.ClrVersions[0]);
                //}
                if (dacLocation == null) dacLocation = dt.ClrVersions[0].TryDownloadDac();

                WriteMessage(string.Format("Loaded DAC: {0}", dacLocation));

                //var runtime = dt.CreateRuntime(dacLocation);
                var runtime = CreateRuntimeHack(dt, dacLocation, 4, 6);

                var heap = runtime.GetHeap();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                //var typesList = new HashSet<string>(StringComparer.Ordinal);
                var sizes = new Dictionary<string, Tuple<string, int, int>>(StringComparer.Ordinal);
                var sizes2 = new Dictionary<string, Tuple<string, int, int>>(StringComparer.Ordinal);
                var typesList = new Dictionary<string, int>();

                var i = 0L;

                WriteMessage("Dumping strings...");
                using (var md5 = System.Security.Cryptography.MD5.Create())
                {
                    foreach (var addr in heap.EnumerateObjects())
                    {
                        try
                        {
                            var type = heap.GetObjectType(addr);
                            if (type != null)
                            {

                                if (!typesList.ContainsKey(type.Name))
                                {
                                    typesList.Add(type.Name, 1);
                                }
                                else
                                {
                                    typesList[type.Name] = typesList[type.Name] + 1;
                                }
                                if (type.Name == "System.String")
                                {
                                    var str = (string)type.GetValue(addr);
                                    if (str.Length > 100)
                                    {
                                        var bytes = System.Text.Encoding.UTF8.GetBytes(str);
                                        var hash = Convert.ToBase64String(md5.ComputeHash(bytes));
                                        if (!sizes.ContainsKey(hash))
                                        {
                                            var fn = "C:\\dbg\\str\\" + (i++) + ".txt";
                                            sizes.Add(hash, Tuple.Create(fn, str.Length, 1));
                                            if (!File.Exists(fn))
                                            {
                                                File.WriteAllText(fn, str);
                                            }
                                        }
                                        else
                                        {
                                            var old = sizes[hash];
                                            sizes[hash] = Tuple.Create(old.Item1, old.Item2, old.Item3 + 1);
                                        }
                                    }
                                }
                                else
                                {
                                    //if (type.Name == "System.Char[]")
                                    //{
                                    //    //var str2 = (System.Char[])type.GetValue(addr);
                                    //    //char[] cArray = System.Text.Encoding.ASCII.GetString(type.GetValue(addr));
                                    //    if (type.GetArrayLength(addr) > 100)
                                    //    {
                                    //        string str2 = string.Empty;
                                    //        for (int ii = 0; ii < type.GetArrayLength(addr); ii++)
                                    //        {
                                    //            str2 = str2 + type.GetArrayElementValue(addr, ii);
                                    //            if ((str2.StartsWith("<file><name>")) && (str2.Contains("</name>")))
                                    //                break;
                                    //        }
                                    //        var bytes2 = System.Text.Encoding.UTF8.GetBytes(str2);
                                    //        var hash2 = Convert.ToBase64String(md5.ComputeHash(bytes2));
                                    //        if (!sizes2.ContainsKey(hash2))
                                    //        {
                                    //            var fn2 = "C:\\dbg\\char-arr\\" + (i++) + ".txt";
                                    //            sizes2.Add(hash2, Tuple.Create(fn2, str2.Length, 1));
                                    //            if (!File.Exists(fn2))
                                    //            {
                                    //                File.WriteAllText(fn2, str2.ToString());
                                    //            }
                                    //            if (str2.StartsWith("<file><name>"))
                                    //            {
                                    //                var fn3 = "C:\\dbg\\char-arr\\file\\" + (i++) + ".txt";
                                    //                if (!File.Exists(fn3))
                                    //                {
                                    //                    File.WriteAllText(fn3, str2.ToString());
                                    //                }
                                    //            }
                                    //        }
                                    //        else
                                    //        {
                                    //            var old2 = sizes2[hash2];
                                    //            sizes2[hash2] = Tuple.Create(old2.Item1, old2.Item2, old2.Item3 + 1);
                                    //        }

                                    //    }
                                    //}
                                    //else
                                    //{


                                    //}

                                    //if (type.Name.Contains("System.Xml.XmlText"))
                                    //{
                                    //    System.Threading.Thread.Sleep(1);
                                    //}
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteMessage(string.Format("Exception (i:{0} addr:{1}): {2}", i.ToString(), addr.ToString(), ex.ToString()));
                        }
                    }
                }

                var t = 0L;

                for (int ii = 0; ii < typesList.Count; ii++)
                {
                    WriteMessage(string.Format("Type: " + typesList.ElementAt(ii).Key.ToString() + ", " + typesList.ElementAt(ii).Value.ToString()));
                }
                int fileCount = 0;
                WriteMessage("String");
                //foreach (var item in sizes.Values.OrderByDescending(x => x.Item2 * x.Item3))
                bool less20 = true;
                //foreach (var item in sizes.Values.OrderByDescending(x => x.Item3))
                foreach (var item in sizes.Values.OrderByDescending(x => x.Item2 * x.Item3))
                {
                    fileCount++;
                    t += item.Item2 * 2 * item.Item3;
                    WriteMessage(string.Format("{0}: {1}x{2} = {3}", item.Item1, item.Item2 * 2, item.Item3, (ulong)item.Item2 * 2UL * (ulong)item.Item3));

                    if (less20)
                    {
                        System.IO.FileInfo file = new System.IO.FileInfo("C:\\dbg\\str\\dumps\\");
                        file.Directory.Create(); // If the directory already exists, this method does nothing.
                        string result = Path.GetFileName(item.Item1);
                        System.IO.File.Copy(item.Item1, "C:\\dbg\\str\\dumps\\" + result);
                    }

                    if (fileCount == 20)
                    {
                        Console.WriteLine("Paused...press enter to continue");
                        Console.ReadLine();
                        less20 = false;
                    }
                }
                WriteMessage(string.Format("String Total: {0}", t));

                //int fileCount2 = 0;
                //WriteMessage("Char[]");
                //foreach (var item in sizes2.Values.OrderByDescending(x => x.Item2 * x.Item3))
                //{
                //    fileCount2++;
                //    t += item.Item2 * 2 * item.Item3;
                //    WriteMessage(string.Format("{0}: {1}x{2} = {3}", item.Item1, item.Item2 * 2, item.Item3, (ulong)item.Item2 * 2UL * (ulong)item.Item3));
                //    if (fileCount2 == 20)
                //    {
                //        Console.WriteLine("Paused...press enter to continue");
                //        Console.ReadLine();
                //    }
                //}
                //WriteMessage(string.Format("Char[] Total: {0}", t));

                Console.WriteLine("PRESS ENTER");
                Console.ReadLine();
            }
        }

        static void WriteMessage(string message)
        {
            Console.WriteLine(message);
            using (System.IO.StreamWriter w = System.IO.File.AppendText("C:\\dbg\\str\\Console.txt"))
            {
                w.WriteLine(System.DateTime.Now + " - " + message);
                w.Flush();
                w.Close();
            }
        }

        public static ClrRuntime CreateRuntimeHack(this DataTarget target, string dacLocation, int major, int minor)
        {
            string dacFileNoExt = Path.GetFileNameWithoutExtension(dacLocation);
            if (dacFileNoExt.Contains("mscordacwks") && major == 4 && minor >= 5)
            {
                Type dacLibraryType = typeof(DataTarget).Assembly.GetType("Microsoft.Diagnostics.Runtime.DacLibrary");
                object dacLibrary = Activator.CreateInstance(dacLibraryType, target, dacLocation);
                Type v45RuntimeType = typeof(DataTarget).Assembly.GetType("Microsoft.Diagnostics.Runtime.Desktop.V45Runtime");
                object runtime = Activator.CreateInstance(v45RuntimeType, target, dacLibrary);
                return (ClrRuntime)runtime;
            }
            else
            {
                return target.CreateRuntime(dacLocation);
            }
        }
    }
}
