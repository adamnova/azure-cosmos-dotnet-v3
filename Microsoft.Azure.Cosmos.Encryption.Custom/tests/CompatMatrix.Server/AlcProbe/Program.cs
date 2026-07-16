// SPIKE probe (Option D feasibility): can the two DIFFERENT versions of the ONE transitive dep that
// the two Encryption.Custom packages disagree on (Microsoft.Data.Encryption.Cryptography 0.2.0-pre
// vs 2.0.0-pre015) be loaded SIDE-BY-SIDE in a single process via AssemblyLoadContext? If not,
// single-process is impossible; if yes, we then judge whether it is WORTH it vs separate processes.
//
//   dotnet run           # auto-resolves both crypto DLLs from the NuGet global-packages folder
//   dotnet run -- <oldDll> <newDll>
using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;

(string oldDll, string newDll) = args.Length >= 2 ? (args[0], args[1]) : ResolveFromNugetCache();
Console.WriteLine($"OLD dll: {oldDll}");
Console.WriteLine($"NEW dll: {newDll}");

var alcOld = new VersionAlc(Path.GetDirectoryName(oldDll)!, "old-crypto");
var alcNew = new VersionAlc(Path.GetDirectoryName(newDll)!, "new-crypto");

Assembly aOld = alcOld.LoadFromAssemblyPath(oldDll);
Assembly aNew = alcNew.LoadFromAssemblyPath(newDll);

Console.WriteLine($"OLD  ctx={AssemblyLoadContext.GetLoadContext(aOld)?.Name}  {aOld.GetName().Name} v{aOld.GetName().Version}");
Console.WriteLine($"NEW  ctx={AssemblyLoadContext.GetLoadContext(aNew)?.Name}  {aNew.GetName().Name} v{aNew.GetName().Version}");

// The SAME full type name resolves to TWO distinct runtime types (different assembly identity).
// This is the crux: any value of such a type cannot be passed between the two version worlds as a
// statically-typed object; it must cross as a primitive (bytes/JSON) or via reflection.
Type? tOld = aOld.GetType("Microsoft.Data.Encryption.Cryptography.EncryptionType");
Type? tNew = aNew.GetType("Microsoft.Data.Encryption.Cryptography.EncryptionType");
Console.WriteLine($"Same full name, same runtime Type? {ReferenceEquals(tOld, tNew)}  (tOld==null:{tOld is null}, tNew==null:{tNew is null})");
Console.WriteLine($"  tOld.Assembly = v{tOld?.Assembly.GetName().Version}");
Console.WriteLine($"  tNew.Assembly = v{tNew?.Assembly.GetName().Version}");
Console.WriteLine("COEXIST=OK (both versions loaded live in ONE process)");

static (string, string) ResolveFromNugetCache()
{
    var psi = new ProcessStartInfo("dotnet", "nuget locals global-packages --list") { RedirectStandardOutput = true, UseShellExecute = false };
    using Process p = Process.Start(psi)!;
    string outp = p.StandardOutput.ReadToEnd();
    p.WaitForExit();
    string gp = outp.Split(':', 2)[1].Trim().TrimEnd('\r', '\n');
    string cryptoRoot = Path.Combine(gp, "microsoft.data.encryption.cryptography");
    string[] versions = Directory.GetDirectories(cryptoRoot).OrderBy(d => d).ToArray();

    // Lowest versioned dir = 0.2.0-pre (netstandard2.0 only); highest = 2.0.0-pre015 (has net8.0).
    static string BestDll(string versionDir)
        => new[] { "net8.0", "net6.0", "netstandard2.0", "net46" }
            .Select(tfm => Path.Combine(versionDir, "lib", tfm, "Microsoft.Data.Encryption.Cryptography.dll"))
            .First(File.Exists);

    return (BestDll(versions.First()), BestDll(versions.Last()));
}

// Each ALC resolves the crypto assembly from its OWN version folder. (Transitive deps are NOT wired
// up here on purpose; we only need the assembly identity to answer the coexistence question.)
internal sealed class VersionAlc : AssemblyLoadContext
{
    private readonly string dir;

    public VersionAlc(string dir, string name)
        : base(name, isCollectible: false) => this.dir = dir;

    protected override Assembly? Load(AssemblyName an)
    {
        string candidate = Path.Combine(this.dir, an.Name + ".dll");
        return File.Exists(candidate) ? this.LoadFromAssemblyPath(candidate) : null; // else fall through to Default
    }
}
