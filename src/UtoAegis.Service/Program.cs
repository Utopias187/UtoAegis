using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace UtoAegis.Service;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var validateOnly = args.Any(argument =>
            string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase));
        var hostArguments = args
            .Where(argument =>
                !string.Equals(argument, "--validate-config", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = hostArguments,
            ContentRootPath = AppContext.BaseDirectory
        });
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "UtoAegis";
        });

        ServiceConfiguration configuration;
        try
        {
            configuration = ServiceConfiguration.Load(
                builder.Configuration,
                AppContext.BaseDirectory);
        }
        catch (ServiceConfigurationException exception)
        {
            Console.Error.WriteLine($"Configuration error: {exception.Message}");
            return 2;
        }

        if (validateOnly)
        {
            Console.WriteLine(
                $"Configuration valid: monitor={configuration.MonitorRoot}; " +
                $"response={configuration.ResponsePolicy.Mode}; " +
                $"recursive={configuration.Recursive}.");
            return 0;
        }

        builder.Services.AddSingleton(configuration);
        builder.Services.AddHostedService<ServiceWorker>();
        using var host = builder.Build();
        await host.RunAsync();
        return 0;
    }
}
