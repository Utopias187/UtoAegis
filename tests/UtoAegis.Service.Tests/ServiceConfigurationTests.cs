using Microsoft.Extensions.Configuration;
using UtoAegis.Core.Response;

namespace UtoAegis.Service.Tests;

[TestClass]
public sealed class ServiceConfigurationTests
{
    private string testDirectory = null!;
    private string monitorRoot = null!;
    private string externalContentStore = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Service.Tests",
            Guid.NewGuid().ToString("N"));
        monitorRoot = Path.Combine(testDirectory, "monitored");
        externalContentStore = testDirectory + "-content";
        Directory.CreateDirectory(monitorRoot);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }

        if (Directory.Exists(externalContentStore))
        {
            Directory.Delete(externalContentStore, recursive: true);
        }
    }

    [TestMethod]
    public void Load_MinimumConfiguration_DefaultsToObserveOnly()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db"
        });

        var result = ServiceConfiguration.Load(configuration, testDirectory);

        Assert.AreEqual(ResponseMode.ObserveOnly, result.ResponsePolicy.Mode);
        Assert.AreEqual(Path.Combine(testDirectory, "state", "reputation.db"), result.DatabasePath);
        Assert.IsTrue(result.Recursive);
        Assert.IsTrue(result.RunInitialScan);
    }

    [TestMethod]
    public void Load_QuarantineWithoutVault_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:Response:Mode"] = "Quarantine"
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "requires VaultPath");
    }

    [TestMethod]
    public void Load_VaultInsideMonitorRoot_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:VaultPath"] = Path.Combine(monitorRoot, "vault")
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "outside MonitorRoot");
    }

    [TestMethod]
    public void Load_WritableDatabaseInsideMonitorRoot_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = Path.Combine(monitorRoot, "reputation.db")
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "outside MonitorRoot");
    }

    [TestMethod]
    public void Load_SignatureInsideWritableStateDirectory_Throws()
    {
        var stateDirectory = Path.Combine(testDirectory, "state");
        Directory.CreateDirectory(stateDirectory);
        var signaturePath = Path.Combine(stateDirectory, "signatures.jsonl");
        File.WriteAllText(signaturePath, "{}\n");
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = Path.Combine(stateDirectory, "reputation.db"),
            ["UtoAegis:SignaturePath"] = signaturePath
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "outside writable state directories");
    }

    [TestMethod]
    public void Load_WritableInstallationDirectory_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = Path.Combine(testDirectory, "reputation.db")
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "installation directory");
    }

    [TestMethod]
    public void Load_WithoutDetectionSource_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "detection source");
    }

    [TestMethod]
    public void Load_ManagedContentConfiguration_ResolvesStoreAndTrustedKey()
    {
        var keyPath = Path.Combine(testDirectory, "keys", "release.pem");
        Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
        File.WriteAllText(keyPath, "test public key");
        var contentStorePath = externalContentStore;
        Directory.CreateDirectory(contentStorePath);
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:ContentStorePath"] = contentStorePath,
            ["UtoAegis:TrustedSigningKeys:0:KeyId"] = "release-key-1",
            ["UtoAegis:TrustedSigningKeys:0:PublicKeyPath"] = keyPath
        });

        var result = ServiceConfiguration.Load(configuration, testDirectory);

        Assert.IsNull(result.DatabasePath);
        Assert.IsNull(result.SignaturePath);
        Assert.IsNotNull(result.ContentStorePath);
        Assert.AreEqual(keyPath, result.TrustedSigningKeyPaths["release-key-1"]);
        CollectionAssert.Contains(
            result.OperationalExclusions.ToArray(),
            result.ContentStorePath);
    }

    [TestMethod]
    public void Load_ManagedContentWithDirectPath_Throws()
    {
        var keyPath = Path.Combine(testDirectory, "release.pem");
        File.WriteAllText(keyPath, "test public key");
        var contentStorePath = externalContentStore;
        Directory.CreateDirectory(contentStorePath);
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:ContentStorePath"] = contentStorePath,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:TrustedSigningKeys:0:KeyId"] = "release-key-1",
            ["UtoAegis:TrustedSigningKeys:0:PublicKeyPath"] = keyPath
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "cannot be combined");
    }

    [TestMethod]
    public void Load_ManagedContentWithoutTrustedKey_Throws()
    {
        var contentStorePath = externalContentStore;
        Directory.CreateDirectory(contentStorePath);
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:ContentStorePath"] = contentStorePath
        });

        var exception = Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));

        StringAssert.Contains(exception.Message, "requires at least one");
    }

    [TestMethod]
    public void Load_ResponseSafetySettings_AreParsed()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:VaultPath"] = "vault",
            ["UtoAegis:Response:Mode"] = "DryRunQuarantine",
            ["UtoAegis:Response:AllowlistedPathPrefixes:0"] = "allowed",
            ["UtoAegis:Response:AllowlistedSha256:0"] = new string('A', 64),
            ["UtoAegis:Response:MaxActionsPerWindow"] = "7",
            ["UtoAegis:Response:RateLimitWindowSeconds"] = "120"
        });

        var result = ServiceConfiguration.Load(configuration, testDirectory);

        Assert.AreEqual(ResponseMode.DryRunQuarantine, result.ResponsePolicy.Mode);
        Assert.AreEqual(7, result.ResponsePolicy.MaxActionsPerWindow);
        Assert.AreEqual(TimeSpan.FromMinutes(2), result.ResponsePolicy.RateLimitWindow);
        Assert.HasCount(1, result.ResponsePolicy.AllowlistedPathPrefixes);
        Assert.AreEqual(
            Path.Combine(testDirectory, "allowed"),
            result.ResponsePolicy.AllowlistedPathPrefixes[0]);
        Assert.IsTrue(result.ResponsePolicy.AllowlistedSha256.Contains(new string('a', 64)));
    }

    [TestMethod]
    public void Load_InvalidHealthInterval_Throws()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:HealthIntervalSeconds"] = "1"
        });

        Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(configuration, testDirectory));
    }

    [TestMethod]
    public void Load_InvalidWatcherLimits_ThrowsBeforeServiceStartup()
    {
        var invalidQueue = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:QueueCapacity"] = "0"
        });
        var invalidConcurrency = BuildConfiguration(new Dictionary<string, string?>
        {
            ["UtoAegis:MonitorRoot"] = monitorRoot,
            ["UtoAegis:DatabasePath"] = "state/reputation.db",
            ["UtoAegis:MaximumConcurrency"] = "100"
        });

        Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(invalidQueue, testDirectory));
        Assert.ThrowsExactly<ServiceConfigurationException>(() =>
            ServiceConfiguration.Load(invalidConcurrency, testDirectory));
    }

    private static IConfiguration BuildConfiguration(
        IDictionary<string, string?> values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
}
