using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace VeritasScanner
{
    internal enum Category
    {
        Process,
        Memory,
        Recent,
        Temp
    }

    internal enum SignatureKind
    {
        Module,
        Client
    }

    internal sealed class Finding
    {
        public Category Kind;
        public string Name;
        public string Location;
        public DateTime Time;
        public bool Flagged;
        public bool IsClient;
    }

    internal sealed class Rule
    {
        public string Name;
        public SignatureKind Kind;
        public int[] Core;
        public int MinCoreHits;
        public int MinDistinctCore;
        public int[] Support;
        public int MinSupport;
    }

    internal sealed class TokenEntry
    {
        public int Id;
        public byte[] Ascii;
        public byte[] Wide;
        public bool StrictLeft;
        public bool LowerStart;
    }

    internal sealed class Region
    {
        public long Start;
        public long Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr process, IntPtr address, out MemoryBasicInformation info, IntPtr length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, IntPtr size, out IntPtr bytesRead);
    }

    internal static class Program
    {
        private const int HitCap = 16;

        private static readonly string[] Keywords = new string[]
        {
            "processhacker",
            "systeminformer",
            "cheatengine",
            "extremeinjector",
            "xenosinjector",
            "dllinjector",
            "httpdebugger",
            "autoclicker",
            "liquidbounce",
            "wurstclient",
            "futureclient",
            "meteorclient",
            "vapeclient",
            "ghostclient",
            "ramdumper",
            "scyllahide",
            "xenos",
            "winject",
            "injector",
            "kdmapper",
            "x64dbg",
            "x32dbg",
            "ollydbg",
            "dnspy",
            "fiddler",
            "aristois",
            "vapelite",
            "doomsday",
            "slinky",
            "artmoney"
        };

        private static readonly string[] WatchedExtensions = new string[] { ".jar", ".exe" };

        private static readonly List<string> TokenTexts = new List<string>();
        private static readonly Dictionary<string, int> TokenIndex = new Dictionary<string, int>(StringComparer.Ordinal);

        private static readonly string[] Framework = new string[]
        {
            "ModuleManager",
            "ModuleCategory",
            "ToggleModule",
            "ClickGui",
            "ClickGUI",
            "NumberSetting",
            "BooleanSetting",
            "ModeSetting",
            "SliderSetting",
            "KeybindSetting"
        };

        private static readonly List<Rule> Rules = new List<Rule>
        {
            ModuleRule("TriggerBot",
                new string[] { "TriggerBot", "Trigger Bot", "triggerbot" },
                new string[] { "Trigger Delay", "Hit Delay", "Only Weapon", "Weapon Only", "Check Shield", "Hit Chance", "Crosshair Target", "setKeyBindState", "keyBindAttack", "ClientTickEvent" }),
            ModuleRule("KillAura",
                new string[] { "KillAura", "Killaura", "killaura", "Kill Aura" },
                new string[] { "Attack Range", "Swing Range", "Rotation Mode", "Target Mode", "AutoBlock", "Auto Block", "Max Targets", "Keep Sprint", "Through Walls", "Aim Point" }),
            ModuleRule("Reach",
                new string[] { "ReachDistance", "Reach Distance", "ReachHack", "AttackReach" },
                new string[] { "Reach Range", "Hitbox Expand", "Attack Distance", "Block Reach", "Min Reach", "Max Reach", "Reach Min", "Reach Max" }),
            ModuleRule("Velocity",
                new string[] { "VelocityHack", "Velocity Modifier", "AntiKnockback", "Anti Knockback", "NoKnockback" },
                new string[] { "Horizontal Velocity", "Vertical Velocity", "Knockback Reduction", "Cancel Velocity", "Velocity Chance" }),
            ModuleRule("AimAssist",
                new string[] { "AimAssist", "Aim Assist", "aimassist" },
                new string[] { "Aim Smoothing", "Max Angle", "Angle Smoothing", "Yaw Speed", "Pitch Speed", "Rotation Smoothing", "Angle Velocity", "Sticky Target", "Aim Speed", "Target Fov", "RenderTickEvent", "setAngles" }),
            ModuleRule("AutoClicker",
                new string[] { "AutoClicker", "Auto Clicker", "autoclicker" },
                new string[] { "Min CPS", "Max CPS", "Left Click", "Right Click", "Jitter", "Click Delay", "Randomization", "Block Hit", "Inventory Fill" }),
            ModuleRule("Health Indicators",
                new string[] { "Health Indicators", "HealthIndicators" },
                new string[] { "Indicator Color", "Show Hearts", "Health Display", "Render Health", "Heart Color" }),
            ModuleRule("Swing Speed",
                new string[] { "Swing Speed", "SwingSpeed" },
                new string[] { "Swing Animation", "Animation Speed", "Slow Swing", "Fast Swing", "Swing Delay" }),
            ModuleRule("Scaffold",
                new string[] { "ScaffoldWalk", "Scaffold Walk", "ScaffoldModule" },
                new string[] { "Tower Mode", "Safe Walk", "Place Delay", "Expand Length", "Sneak Mode", "Rotation Mode" }),
            ModuleRule("AutoTotem",
                new string[] { "AutoTotem", "Auto Totem" },
                new string[] { "Totem Delay", "Health Threshold", "Offhand Mode", "Swap Delay" }),
            ModuleRule("AutoCrystal",
                new string[] { "AutoCrystal", "Auto Crystal" },
                new string[] { "Crystal Delay", "Place Range", "Break Range", "Min Damage", "Max Self Damage" }),
            ClientRule("LiquidBounce", new string[] { "net/ccbluex/liquidbounce", "net.ccbluex.liquidbounce", "LiquidBounce" }),
            ClientRule("Wurst", new string[] { "net/wurstclient", "net.wurstclient", "WurstClient" }),
            ClientRule("Meteor", new string[] { "meteordevelopment/meteorclient", "meteordevelopment.meteorclient", "MeteorClient" }),
            ClientRule("Vape", new string[] { "VapeClient", "Vape V4", "VapeLite", "Vape Lite", "vape.gg" }),
            ClientRule("Aristois", new string[] { "Aristois", "aristois.net", "aristois.com" }),
            ClientRule("Future", new string[] { "net/futureclient", "net.futureclient", "FutureClient", "futureclient.net" }),
            ClientRule("Rise", new string[] { "RiseClient", "Rise Client", "riseclient.com" }),
            ClientRule("Raven", new string[] { "RavenB+", "RavenBS", "Raven B+" }),
            ClientRule("Doomsday", new string[] { "DoomsdayClient", "Doomsday Client", "doomsdayclient" }),
            ClientRule("Slinky", new string[] { "SlinkyClient", "Slinky Client" }),
            ClientRule("Astolfo", new string[] { "AstolfoClient", "Astolfo Client" })
        };

        private static readonly int[] ClientMarkers = Toks("net/minecraft/client", "net.minecraft.client", "com/mojang/blaze3d", "com.mojang.blaze3d");

        private static readonly int[] ServerMarkers = Toks("org/bukkit", "org.bukkit", "io/papermc", "org.spigotmc");

        private static readonly TokenEntry[][] Table = BuildTable();

        private static readonly int MaxPatternBytes = ComputeMaxPatternBytes();

        private static readonly string[] TitleHints = new string[] { "minecraft", "lunar client", "badlion", "labymod", "feather client" };

        private static readonly string BannerNoise = "#@%&01$|<>=+";

        private static readonly Random Rng = new Random();

        private static readonly List<Finding> Findings = new List<Finding>();

        private static bool turkish = false;
        private static int javaProcessCount = 0;
        private static int minecraftCount = 0;
        private static int ignoredCount = 0;
        private static bool memoryScanSkipped = false;
        private static string skipReason = string.Empty;
        private static int lastPercent = -1;

        private static int Tok(string text)
        {
            int id;
            if (TokenIndex.TryGetValue(text, out id))
            {
                return id;
            }

            id = TokenTexts.Count;
            TokenTexts.Add(text);
            TokenIndex[text] = id;
            return id;
        }

        private static int[] Toks(params string[] texts)
        {
            return texts.Select(t => Tok(t)).ToArray();
        }

        private static Rule ModuleRule(string name, string[] core, string[] support)
        {
            return new Rule
            {
                Name = name,
                Kind = SignatureKind.Module,
                Core = Toks(core),
                MinCoreHits = 2,
                MinDistinctCore = 1,
                Support = Toks(support.Concat(Framework).Distinct().ToArray()),
                MinSupport = 2
            };
        }

        private static Rule ClientRule(string name, string[] core)
        {
            return new Rule
            {
                Name = name,
                Kind = SignatureKind.Client,
                Core = Toks(core),
                MinCoreHits = 3,
                MinDistinctCore = 2,
                Support = new int[0],
                MinSupport = 0
            };
        }

        private static TokenEntry[][] BuildTable()
        {
            List<TokenEntry>[] working = new List<TokenEntry>[256];

            for (int id = 0; id < TokenTexts.Count; id++)
            {
                string text = TokenTexts[id];
                byte[] ascii = Encoding.ASCII.GetBytes(text);
                byte[] wide = Encoding.Unicode.GetBytes(text);
                int first = ascii[0];

                TokenEntry entry = new TokenEntry
                {
                    Id = id,
                    Ascii = ascii,
                    Wide = wide,
                    StrictLeft = text.IndexOf('/') < 0 && text.IndexOf('.') < 0,
                    LowerStart = first >= 'a' && first <= 'z'
                };

                if (working[first] == null)
                {
                    working[first] = new List<TokenEntry>();
                }
                working[first].Add(entry);
            }

            TokenEntry[][] result = new TokenEntry[256][];
            for (int i = 0; i < 256; i++)
            {
                result[i] = working[i] == null ? null : working[i].ToArray();
            }

            return result;
        }

        private static int ComputeMaxPatternBytes()
        {
            int max = 0;
            foreach (string text in TokenTexts)
            {
                int length = text.Length * 2;
                if (length > max)
                {
                    max = length;
                }
            }
            return max + 4;
        }

        private static string L(string tr, string en)
        {
            return turkish ? tr : en;
        }

        private static int Main()
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
            }
            catch
            {
            }

            Console.Title = "Veritas Scanner v1.3";

            PrintBanner();
            SelectLanguage();

            if (!IsAdministrator())
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("Yönetici izni gerekli.", "Administrator permission is required."));
                Console.WriteLine("  " + L("Programa sağ tıklayıp 'Yönetici olarak çalıştır' seçeneğini seçin.", "Right-click the program and choose 'Run as administrator'."));
                Console.ResetColor();
                Console.WriteLine();
                WaitForEscape(L("Çıkmak için [ESC] tuşuna basın...", "Press [ESC] to exit..."));
                return 1;
            }

            DateTime started = DateTime.Now;

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  " + L("Tarama başlıyor. Lütfen bekleyin...", "Scan is starting. Please wait..."));
            Console.ResetColor();

            ScanProcesses();
            ScanMinecraftMemory();
            ScanRecentFolder();
            ScanTempFolders();

            PrintReport(started);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  " + new string('=', 56));
            Console.ForegroundColor = ConsoleColor.Cyan;
            WaitForEscape(L("Tarama tamamlandı. Çıkmak için [ESC] tuşuna basın...", "Scan complete. Press [ESC] to exit..."));
            return 0;
        }

        private static void WaitForEscape(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  " + message);
            Console.ResetColor();

            while (true)
            {
                try
                {
                    ConsoleKeyInfo key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Escape)
                    {
                        break;
                    }
                }
                catch (InvalidOperationException)
                {
                    Console.ReadLine();
                    break;
                }
            }
        }

        private static void DrawBanner(double noise)
        {
            string[] art = new string[]
            {
                @" __     _______ ____  ___ _____  _    ____  ",
                @" \ \   / / ____|  _ \|_ _|_   _|/ \  / ___| ",
                @"  \ \ / /|  _| | |_) || |  | | / _ \ \___ \ ",
                @"   \ V / | |___|  _ < | |  | |/ ___ \ ___) |",
                @"    \_/  |_____|_| \_\___| |_/_/   \_\____/ "
            };

            ConsoleColor[] palette = new ConsoleColor[]
            {
                ConsoleColor.Magenta,
                ConsoleColor.DarkMagenta,
                ConsoleColor.Cyan,
                ConsoleColor.DarkCyan,
                ConsoleColor.Cyan
            };

            Console.Clear();
            Console.WriteLine();

            for (int row = 0; row < art.Length; row++)
            {
                char[] chars = art[row].ToCharArray();
                for (int c = 0; c < chars.Length; c++)
                {
                    if (chars[c] != ' ' && Rng.NextDouble() < noise)
                    {
                        chars[c] = BannerNoise[Rng.Next(BannerNoise.Length)];
                    }
                }

                Console.ForegroundColor = noise > 0 && Rng.NextDouble() < 0.3 ? ConsoleColor.DarkGray : palette[row];
                Console.WriteLine("    " + new string(chars));
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("    Veritas Scanner v1.3 - Forensic & Client Integrity Suite");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("    " + new string('=', 56));
            Console.ResetColor();
            Console.WriteLine();
        }

        private static void PrintBanner()
        {
            try
            {
                double[] frames = new double[] { 0.35, 0.2, 0.1, 0.0 };
                foreach (double noise in frames)
                {
                    DrawBanner(noise);
                    Thread.Sleep(80);
                }
            }
            catch
            {
                Console.WriteLine();
                Console.WriteLine("    Veritas Scanner v1.3 - Forensic & Client Integrity Suite");
                Console.WriteLine();
            }
        }

        private static void SelectLanguage()
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  Select Language / Dil Seciniz:");
            Console.ResetColor();
            Console.WriteLine("  1 - Türkçe");
            Console.WriteLine("  2 - English");
            Console.WriteLine();

            while (true)
            {
                Console.Write("  > ");
                ConsoleKeyInfo key = Console.ReadKey(true);

                if (key.KeyChar == '1')
                {
                    turkish = true;
                    Console.WriteLine("1");
                    break;
                }

                if (key.KeyChar == '2')
                {
                    turkish = false;
                    Console.WriteLine("2");
                    break;
                }

                Console.WriteLine();
            }
        }

        private static bool IsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        private static void PrintStep(int number, string text)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  [" + number + "/4] " + text);
            Console.ResetColor();
        }

        private static void PrintStatus(int flagged, int review)
        {
            if (flagged > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  [X] " + L("Şüpheli öğe bulundu: ", "Suspicious items found: ") + flagged);
            }
            else if (review > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("İncelenmesi gereken öğe: ", "Items to review: ") + review);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  [OK] " + L("Sorun bulunamadı.", "Nothing found."));
            }
            Console.ResetColor();
        }

        private static string Normalize(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            char[] buffer = value.ToLowerInvariant().Where(c => char.IsLetterOrDigit(c)).ToArray();
            return new string(buffer);
        }

        private static bool OnlyDigits(string value, int from)
        {
            for (int i = from; i < value.Length; i++)
            {
                if (value[i] < '0' || value[i] > '9')
                {
                    return false;
                }
            }
            return true;
        }

        private static bool IsKnownThreat(string value, bool isTitle)
        {
            string normalized = Normalize(value);
            if (normalized.Length == 0)
            {
                return false;
            }

            foreach (string keyword in Keywords)
            {
                if (keyword.Length >= 9)
                {
                    if (normalized.Contains(keyword))
                    {
                        return true;
                    }
                }
                else if (!isTitle)
                {
                    if (normalized == keyword || (normalized.StartsWith(keyword, StringComparison.Ordinal) && OnlyDigits(normalized, keyword.Length)))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static string StripExtension(string name)
        {
            try
            {
                return Path.GetFileNameWithoutExtension(name);
            }
            catch
            {
                return name;
            }
        }

        private static void ScanProcesses()
        {
            PrintStep(1, L("Çalışan programlar kontrol ediliyor...", "Checking running programs..."));

            Process[] processes;
            try
            {
                processes = Process.GetProcesses();
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("Çalışan programlar okunamadı.", "Could not read running programs."));
                Console.ResetColor();
                return;
            }

            int checkedCount = 0;
            int flagged = 0;
            HashSet<string> reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Process process in processes)
            {
                try
                {
                    checkedCount++;
                    string name = process.ProcessName;
                    string title = string.Empty;

                    try
                    {
                        title = process.MainWindowTitle;
                    }
                    catch
                    {
                        title = string.Empty;
                    }

                    if (IsKnownThreat(name, false) || IsKnownThreat(title, true))
                    {
                        if (reported.Add(name + "|" + process.Id))
                        {
                            flagged++;
                            Findings.Add(new Finding
                            {
                                Kind = Category.Process,
                                Name = name + ".exe",
                                Location = string.Empty,
                                Time = DateTime.Now,
                                Flagged = true
                            });

                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("  [X] " + L("Yasaklı program çalışıyor: ", "Prohibited program is running: ") + name + ".exe");
                            Console.ResetColor();
                        }
                    }
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  " + L("Kontrol edilen program sayısı: ", "Programs checked: ") + checkedCount);
            Console.ResetColor();
            PrintStatus(flagged, 0);
        }

        private static void ClearLine()
        {
            try
            {
                Console.Write("\r" + new string(' ', 78) + "\r");
            }
            catch
            {
            }
        }

        private static void DrawProgress(long done, long total)
        {
            int percent = total <= 0 ? 100 : (int)Math.Min(100L, done * 100L / total);
            if (percent == lastPercent)
            {
                return;
            }

            lastPercent = percent;
            int filled = percent * 30 / 100;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("\r  [" + new string('#', filled) + new string('-', 30 - filled) + "] " + percent.ToString().PadLeft(3) + "%  " + L("taranıyor", "scanning") + "   ");
            Console.ResetColor();
        }

        private static void ScanMinecraftMemory()
        {
            PrintStep(2, L("Minecraft bellek taraması yapılıyor...", "Scanning Minecraft memory..."));

            List<Process> targets = new List<Process>();
            foreach (string name in new string[] { "javaw", "java" })
            {
                try
                {
                    targets.AddRange(Process.GetProcessesByName(name));
                }
                catch
                {
                }
            }

            javaProcessCount = targets.Count;

            if (targets.Count == 0)
            {
                memoryScanSkipped = true;
                skipReason = L("Java / Minecraft çalışmıyor.", "Java / Minecraft is not running.");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + skipReason);
                Console.WriteLine("      " + L("Bellek taraması yapılmadı. Oyun açıkken tekrar çalıştırın.", "Memory scan skipped. Run again while the game is open."));
                Console.ResetColor();
                return;
            }

            if (!Environment.Is64BitProcess && Environment.Is64BitOperatingSystem)
            {
                memoryScanSkipped = true;
                skipReason = L("64 bit sürüm gerekli.", "A 64-bit build is required.");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + skipReason);
                Console.ResetColor();
                foreach (Process target in targets)
                {
                    target.Dispose();
                }
                return;
            }

            int flagged = 0;

            foreach (Process target in targets)
            {
                try
                {
                    flagged += ScanJavaProcess(target);
                }
                catch
                {
                    ClearLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("  [!] " + L("Bu işlem okunamadı.", "This process could not be read."));
                    Console.ResetColor();
                }
                finally
                {
                    target.Dispose();
                }
            }

            PrintStatus(flagged, 0);
        }

        private static bool TitleLooksLikeMinecraft(string title)
        {
            if (string.IsNullOrEmpty(title))
            {
                return false;
            }

            foreach (string hint in TitleHints)
            {
                if (title.IndexOf(hint, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
            return false;
        }

        private static int SumHits(int[] ids, int[] hits)
        {
            int total = 0;
            foreach (int id in ids)
            {
                total += hits[id];
            }
            return total;
        }

        private static bool IsSatisfied(Rule rule, int[] hits)
        {
            int totalCore = 0;
            int distinct = 0;

            foreach (int id in rule.Core)
            {
                int h = hits[id];
                totalCore += h;
                if (h > 0)
                {
                    distinct++;
                }
            }

            if (totalCore < rule.MinCoreHits || distinct < rule.MinDistinctCore)
            {
                return false;
            }

            int support = 0;
            foreach (int id in rule.Support)
            {
                if (hits[id] > 0)
                {
                    support++;
                }
            }

            return support >= rule.MinSupport;
        }

        private static int ScanJavaProcess(Process process)
        {
            int pid = process.Id;
            string label = process.ProcessName + ".exe (PID " + pid + ")";
            string title = string.Empty;

            try
            {
                title = process.MainWindowTitle;
            }
            catch
            {
                title = string.Empty;
            }

            int flagged = 0;

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("  > " + label);
            Console.ResetColor();

            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    string moduleName = module.ModuleName;
                    if (IsKnownThreat(StripExtension(moduleName), false))
                    {
                        flagged++;
                        Findings.Add(new Finding
                        {
                            Kind = Category.Process,
                            Name = moduleName,
                            Location = label,
                            Time = DateTime.Now,
                            Flagged = true
                        });

                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("  [X] " + L("Şüpheli modül yüklenmiş: ", "Suspicious module loaded: ") + moduleName);
                        Console.ResetColor();
                    }
                }
            }
            catch
            {
            }

            IntPtr handle = NativeMethods.OpenProcess(0x0410, false, pid);
            if (handle == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("Bellek erişimi reddedildi.", "Memory access was denied."));
                Console.ResetColor();
                return flagged;
            }

            int[] hits = new int[TokenTexts.Count];

            try
            {
                List<Region> regions = EnumerateRegions(handle);
                long total = 0;
                foreach (Region region in regions)
                {
                    total += region.Size;
                }

                int chunkSize = 4 * 1024 * 1024;
                int overlap = MaxPatternBytes;
                byte[] buffer = new byte[chunkSize + overlap + 2];
                long done = 0;
                lastPercent = -1;

                DrawProgress(0, total);

                foreach (Region region in regions)
                {
                    long offset = 0;
                    while (offset < region.Size)
                    {
                        long remaining = region.Size - offset;
                        int lead = offset > 0 ? 2 : 0;
                        long readStart = region.Start + offset - lead;
                        long available = remaining + lead;
                        int want = (int)Math.Min((long)chunkSize + overlap + lead, available);
                        IntPtr read;

                        NativeMethods.ReadProcessMemory(handle, new IntPtr(readStart), buffer, new IntPtr(want), out read);
                        int count = (int)read.ToInt64();

                        if (count > lead)
                        {
                            int limit = remaining > chunkSize ? lead + chunkSize : count;
                            if (limit > count)
                            {
                                limit = count;
                            }
                            ScanBuffer(buffer, count, lead, limit, hits);
                        }

                        long advance = remaining <= chunkSize ? remaining : chunkSize;
                        offset += advance;
                        done += advance;
                        DrawProgress(done, total);
                    }
                }

                lastPercent = -1;
                DrawProgress(total, total);
                Console.WriteLine();
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }

            bool confirmedClient = TitleLooksLikeMinecraft(title) || SumHits(ClientMarkers, hits) >= 2;
            bool serverProcess = SumHits(ServerMarkers, hits) >= 2;

            List<Rule> satisfied = Rules.Where(r => IsSatisfied(r, hits)).ToList();

            if (confirmedClient && !serverProcess)
            {
                minecraftCount++;
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine("  " + L("Minecraft istemcisi doğrulandı.", "Minecraft client confirmed."));
                Console.ResetColor();

                foreach (Rule rule in satisfied)
                {
                    flagged++;
                    bool isClient = rule.Kind == SignatureKind.Client;

                    Findings.Add(new Finding
                    {
                        Kind = Category.Memory,
                        Name = rule.Name,
                        Location = label,
                        Time = DateTime.Now,
                        Flagged = true,
                        IsClient = isClient
                    });

                    Console.ForegroundColor = ConsoleColor.Red;
                    if (isClient)
                    {
                        Console.WriteLine("  [~] " + rule.Name + " " + L("istemci izi bulundu", "client trace found") + "  " + L("(yüksek güven)", "(high confidence)"));
                    }
                    else
                    {
                        Console.WriteLine("  [~] " + rule.Name + " " + L("modülü bulundu", "module found") + "  " + L("(yüksek güven)", "(high confidence)"));
                    }
                    Console.ResetColor();
                    Thread.Sleep(60);
                }
            }
            else
            {
                ignoredCount += satisfied.Count > 0 ? 1 : 0;

                Console.ForegroundColor = ConsoleColor.DarkGray;
                if (serverProcess)
                {
                    Console.WriteLine("  " + L("Bu işlem bir sunucu olarak görünüyor, sonuçlar yok sayıldı.", "This process looks like a server, results were ignored."));
                }
                else
                {
                    Console.WriteLine("  " + L("Bu Java işlemi Minecraft istemcisi gibi görünmüyor.", "This Java process does not look like a Minecraft client."));
                }
                Console.ResetColor();
            }

            return flagged;
        }

        private static List<Region> EnumerateRegions(IntPtr handle)
        {
            List<Region> regions = new List<Region>();
            long address = 0;
            long limit = 0x7FFFFFFEFFFFL;
            IntPtr structSize = new IntPtr(Marshal.SizeOf(typeof(MemoryBasicInformation)));

            while (address < limit)
            {
                MemoryBasicInformation info;
                int result = NativeMethods.VirtualQueryEx(handle, new IntPtr(address), out info, structSize);
                if (result == 0)
                {
                    break;
                }

                long start = info.BaseAddress.ToInt64();
                long size = info.RegionSize.ToInt64();
                if (size <= 0)
                {
                    break;
                }

                bool committed = info.State == 0x1000;
                bool privateOrMapped = info.Type == 0x20000 || info.Type == 0x40000;
                bool guarded = (info.Protect & 0x100) != 0;
                bool readable = (info.Protect & (0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80)) != 0;

                if (committed && privateOrMapped && !guarded && readable)
                {
                    regions.Add(new Region { Start = start, Size = size });
                }

                long next = start + size;
                if (next <= address)
                {
                    break;
                }
                address = next;
            }

            return regions;
        }

        private static bool IsLower(int value)
        {
            return value >= 'a' && value <= 'z';
        }

        private static bool IsLetter(int value)
        {
            return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
        }

        private static bool BoundaryOk(TokenEntry entry, int left, int right)
        {
            bool leftOk = true;
            if (entry.StrictLeft)
            {
                leftOk = entry.LowerStart ? !IsLetter(left) : !IsLower(left);
            }

            return leftOk && !IsLower(right);
        }

        private static void ScanBuffer(byte[] buffer, int count, int start, int limit, int[] hits)
        {
            for (int i = start; i < limit; i++)
            {
                TokenEntry[] list = Table[buffer[i]];
                if (list == null)
                {
                    continue;
                }

                for (int k = 0; k < list.Length; k++)
                {
                    TokenEntry entry = list[k];
                    if (hits[entry.Id] >= HitCap)
                    {
                        continue;
                    }

                    int length = entry.Ascii.Length;
                    int remaining = count - i;

                    if (remaining >= length && MatchAscii(buffer, i, entry.Ascii))
                    {
                        int left = i > 0 ? buffer[i - 1] : 0;
                        int right = i + length < count ? buffer[i + length] : 0;

                        if (BoundaryOk(entry, left, right))
                        {
                            hits[entry.Id]++;
                        }
                        continue;
                    }

                    if (remaining >= length * 2 && buffer[i + 1] == 0 && MatchWide(buffer, i, entry.Ascii))
                    {
                        int left = 0;
                        if (i >= 2 && buffer[i - 1] == 0)
                        {
                            left = buffer[i - 2];
                        }

                        int right = 0;
                        int rightIndex = i + length * 2;
                        if (rightIndex + 1 < count && buffer[rightIndex + 1] == 0)
                        {
                            right = buffer[rightIndex];
                        }

                        if (BoundaryOk(entry, left, right))
                        {
                            hits[entry.Id]++;
                        }
                    }
                }
            }
        }

        private static bool MatchAscii(byte[] buffer, int index, byte[] pattern)
        {
            for (int j = 1; j < pattern.Length; j++)
            {
                if (buffer[index + j] != pattern[j])
                {
                    return false;
                }
            }
            return true;
        }

        private static bool MatchWide(byte[] buffer, int index, byte[] pattern)
        {
            for (int j = 1; j < pattern.Length; j++)
            {
                if (buffer[index + j * 2] != pattern[j] || buffer[index + j * 2 + 1] != 0)
                {
                    return false;
                }
            }
            return true;
        }

        private static void ScanRecentFolder()
        {
            PrintStep(3, L("Son kullanılan dosyalar kontrol ediliyor (son 24 saat)...", "Checking recently used files (last 24 hours)..."));

            string recent = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            DateTime threshold = DateTime.Now.AddHours(-24);
            int flagged = 0;
            int review = 0;
            int checkedCount = 0;

            string[] files = null;
            try
            {
                if (!string.IsNullOrEmpty(recent) && Directory.Exists(recent))
                {
                    files = Directory.GetFiles(recent);
                }
            }
            catch
            {
                files = null;
            }

            if (files == null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("Son kullanılanlar klasörüne erişilemedi.", "Could not access the recent files folder."));
                Console.ResetColor();
                return;
            }

            foreach (string file in files)
            {
                try
                {
                    checkedCount++;
                    FileInfo info = new FileInfo(file);
                    DateTime stamp = info.LastWriteTime > info.CreationTime ? info.LastWriteTime : info.CreationTime;

                    if (stamp < threshold)
                    {
                        continue;
                    }

                    string target = info.Name;
                    if (target.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        target = target.Substring(0, target.Length - 4);
                    }

                    string extension = Path.GetExtension(target);
                    if (!WatchedExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    bool threat = IsKnownThreat(StripExtension(target), false);
                    if (threat)
                    {
                        flagged++;
                    }
                    else
                    {
                        review++;
                    }

                    Findings.Add(new Finding
                    {
                        Kind = Category.Recent,
                        Name = target,
                        Location = string.Empty,
                        Time = stamp,
                        Flagged = threat
                    });

                    Console.ForegroundColor = threat ? ConsoleColor.Red : ConsoleColor.Yellow;
                    Console.WriteLine((threat ? "  [X] " : "  [!] ") + target + "  (" + stamp.ToString("dd.MM.yyyy HH:mm") + ")");
                    Console.ResetColor();
                }
                catch
                {
                }
            }

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  " + L("Kontrol edilen kayıt sayısı: ", "Entries checked: ") + checkedCount);
            Console.ResetColor();
            PrintStatus(flagged, review);
        }

        private static void ScanTempFolders()
        {
            PrintStep(4, L("Geçici klasörler kontrol ediliyor (son 24 saat)...", "Checking temporary folders (last 24 hours)..."));

            List<string> roots = new List<string>();
            try
            {
                roots.Add(Path.GetTempPath());
            }
            catch
            {
            }

            try
            {
                roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            }
            catch
            {
            }

            List<string> distinctRoots = roots
                .Where(r => !string.IsNullOrEmpty(r))
                .Select(r => r.TrimEnd(Path.DirectorySeparatorChar))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            DateTime threshold = DateTime.Now.AddHours(-24);
            int flagged = 0;
            int review = 0;
            int checkedCount = 0;
            const int maxDepth = 6;

            foreach (string root in distinctRoots)
            {
                if (!Directory.Exists(root))
                {
                    continue;
                }

                Stack<KeyValuePair<string, int>> pending = new Stack<KeyValuePair<string, int>>();
                pending.Push(new KeyValuePair<string, int>(root, 0));

                while (pending.Count > 0)
                {
                    KeyValuePair<string, int> current = pending.Pop();
                    string[] files;

                    try
                    {
                        files = Directory.GetFiles(current.Key);
                    }
                    catch
                    {
                        files = new string[0];
                    }

                    if (current.Value < maxDepth)
                    {
                        try
                        {
                            foreach (string directory in Directory.GetDirectories(current.Key))
                            {
                                pending.Push(new KeyValuePair<string, int>(directory, current.Value + 1));
                            }
                        }
                        catch
                        {
                        }
                    }

                    foreach (string file in files)
                    {
                        try
                        {
                            checkedCount++;
                            string extension = Path.GetExtension(file);
                            if (!WatchedExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            FileInfo info = new FileInfo(file);
                            DateTime stamp = info.LastWriteTime > info.CreationTime ? info.LastWriteTime : info.CreationTime;
                            if (stamp < threshold)
                            {
                                continue;
                            }

                            bool threat = IsKnownThreat(StripExtension(info.Name), false);
                            if (threat)
                            {
                                flagged++;
                            }
                            else
                            {
                                review++;
                            }

                            Findings.Add(new Finding
                            {
                                Kind = Category.Temp,
                                Name = info.Name,
                                Location = info.DirectoryName,
                                Time = stamp,
                                Flagged = threat
                            });

                            Console.ForegroundColor = threat ? ConsoleColor.Red : ConsoleColor.Yellow;
                            Console.WriteLine((threat ? "  [X] " : "  [!] ") + info.Name + "  (" + stamp.ToString("dd.MM.yyyy HH:mm") + ")");
                            Console.ResetColor();
                        }
                        catch
                        {
                        }
                    }
                }
            }

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("  " + L("Kontrol edilen dosya sayısı: ", "Files checked: ") + checkedCount);
            Console.ResetColor();
            PrintStatus(flagged, review);
        }

        private static string CategoryName(Finding finding)
        {
            switch (finding.Kind)
            {
                case Category.Process:
                    return L("Program", "Program");
                case Category.Memory:
                    return finding.IsClient ? L("Bellek / İstemci", "Memory / Client") : L("Bellek / Modül", "Memory / Module");
                case Category.Recent:
                    return L("Son Kullanılan", "Recent");
                default:
                    return L("Geçici", "Temp");
            }
        }

        private static void PrintReport(DateTime started)
        {
            TimeSpan elapsed = DateTime.Now - started;

            int flaggedCount = Findings.Count(f => f.Flagged);
            int reviewCount = Findings.Count(f => !f.Flagged);
            int moduleCount = Findings.Count(f => f.Kind == Category.Memory && !f.IsClient);
            int clientCount = Findings.Count(f => f.Kind == Category.Memory && f.IsClient);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  " + new string('=', 56));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  " + L("TARAMA SONUCU", "SCAN RESULT"));
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  " + new string('=', 56));
            Console.ResetColor();

            Console.WriteLine("  " + L("Süre                    : ", "Duration                : ") + elapsed.TotalSeconds.ToString("0.0") + " " + L("sn", "s"));
            Console.WriteLine("  " + L("Java işlemleri         : ", "Java processes          : ") + javaProcessCount);
            Console.WriteLine("  " + L("Doğrulanan istemciler  : ", "Verified clients        : ") + minecraftCount);
            Console.WriteLine("  " + L("Hile modülleri         : ", "Cheat modules           : ") + moduleCount);
            Console.WriteLine("  " + L("Hile istemci izleri    : ", "Cheat client traces     : ") + clientCount);
            Console.WriteLine("  " + L("Yasaklı programlar     : ", "Prohibited programs     : ") + Findings.Count(f => f.Kind == Category.Process));
            Console.WriteLine("  " + L("Son kullanılan izler   : ", "Recent file traces     : ") + Findings.Count(f => f.Kind == Category.Recent));
            Console.WriteLine("  " + L("Geçici klasör izleri   : ", "Temp folder traces     : ") + Findings.Count(f => f.Kind == Category.Temp));
            Console.WriteLine("  " + L("Yok sayılan sonuçlar   : ", "Ignored results         : ") + ignoredCount);
            Console.WriteLine();

            Console.ForegroundColor = flaggedCount > 0 ? ConsoleColor.Red : ConsoleColor.Green;
            Console.WriteLine("  " + L("Şüpheli bulgular        : ", "Suspicious findings    : ") + flaggedCount);
            Console.ForegroundColor = reviewCount > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
            Console.WriteLine("  " + L("İncelenecek öğeler      : ", "Items to review        : ") + reviewCount);
            Console.ResetColor();

            if (memoryScanSkipped)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("Bellek taraması yapılamadı: ", "Memory scan not performed: ") + skipReason);
                Console.ResetColor();
            }

            if (flaggedCount > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  " + L("Şüpheli bulgu listesi:", "Suspicious findings list:"));
                foreach (Finding finding in Findings.Where(f => f.Flagged))
                {
                    string place = string.IsNullOrEmpty(finding.Location) ? string.Empty : "  " + finding.Location;
                    Console.WriteLine("   - [" + CategoryName(finding) + "] " + finding.Name + place);
                }
                Console.ResetColor();
            }

            Console.WriteLine();
            if (flaggedCount > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  [X] " + L("SONUÇ: Bu bilgisayarda şüpheli izler bulundu.", "VERDICT: Suspicious traces were found on this computer."));
            }
            else if (reviewCount > 0 || memoryScanSkipped)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("  [!] " + L("SONUÇ: Bilinen tehdit yok, ancak bazı öğeler incelenmeli.", "VERDICT: No known threats, but some items should be reviewed."));
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("  [OK] " + L("SONUÇ: Bilgisayar temiz görünüyor.", "VERDICT: The computer looks clean."));
            }
            Console.ResetColor();
        }
    }
}
