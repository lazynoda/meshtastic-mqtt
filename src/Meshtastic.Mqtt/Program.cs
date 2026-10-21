using System.Runtime.InteropServices;
using System.Text;
using Meshtastic.Mqtt;
using MQTTnet.Server;
using Serilog;
using Serilog.Core;
using Serilog.Formatting.Compact;

return await Cli.RunAsync(args);

static class Cli
{
    const string Usage = """
        Usage:
          Meshtastic.Mqtt [config.yaml]       run the broker (or set MESHTASTIC_MQTT_CONFIG)
          Meshtastic.Mqtt hash-password       read a password from stdin, print its hash for the config
        """;

    public static async Task<int> RunAsync(string[] args)
    {
        if (args is ["hash-password"])
            return HashPassword();
        if (args is ["-h"] or ["--help"])
        {
            Console.Out.WriteLine(Usage);
            return 0;
        }
        if (args.Length > 1)
        {
            Console.Error.WriteLine(Usage);
            return 2;
        }

        var path = args.Length == 1 ? args[0] : Environment.GetEnvironmentVariable(ConfigLoader.EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(path))
        {
            Console.Error.WriteLine($"No config file: pass its path as the only argument or set {ConfigLoader.EnvironmentVariable}.");
            Console.Error.WriteLine(Usage);
            return 2;
        }

        BrokerConfig config;
        try
        {
            config = ConfigLoader.LoadFile(path);
        }
        catch (ConfigException ex)
        {
            Console.Error.WriteLine($"Invalid config '{path}':{Environment.NewLine}{ex.Message}");
            return 1;
        }

        await using var logger = new LoggerConfiguration()
            .MinimumLevel.ControlledBy(new LoggingLevelSwitch(config.MinimumLevel))
            .WriteTo.Console(new RenderedCompactJsonFormatter())
            .CreateLogger();

        return await RunBrokerAsync(config, logger);
    }

    static async Task<int> RunBrokerAsync(BrokerConfig config, Logger logger)
    {
        await using var drops = new DropCounters(logger);

        BrokerServer.Built built;
        try
        {
            built = BrokerServer.Create(config, logger, drops: drops);
        }
        catch (FilterException ex)
        {
            // The rules file is missing or is not valid: the broker does not start, like the config.
            Console.Error.WriteLine($"Invalid filters '{config.Filters?.File}':{Environment.NewLine}"
                + string.Join(Environment.NewLine, ex.Errors.Select(error => "- " + error)));
            return 1;
        }
        catch (Re2UnavailableException ex)
        {
            // The rules file needs Google RE2, and its native library is not there.
            Console.Error.WriteLine($"Cannot start the filters '{config.Filters?.File}': {ex.Message}");
            return 1;
        }

        using var server = built.Server;
        using var filter = built.Filter;

        var stop = new TaskCompletionSource();
        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; stop.TrySetResult(); });
        using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; stop.TrySetResult(); });
        // SIGHUP reloads the rules file: the operator changes it and the new rules are in force at once.
        using var sighup = PosixSignalRegistration.Create(PosixSignal.SIGHUP, ctx => { ctx.Cancel = true; filter.ReloadNow(); });

        try
        {
            await server.StartAsync();
        }
        catch (Exception ex)
        {
            logger.Fatal("Cannot start the MQTT listener on {Address}:{Port}: {Error}", config.BindAddress, config.Listener.Port, ex.Message);
            return 1;
        }

        // Every limit of the configuration is on this line, so the operator sees what the broker is
        // running with (the exempt ranges are listed, not counted). The limits are also attached as a
        // structured property, so the log store keeps them as data and not only as text.
        StartupLine.Write(logger, config, filter);

        await stop.Task;
        logger.Information("Shutting down");
        await server.StopAsync();
        return 0;
    }

    static int HashPassword()
    {
        string? password;
        if (Console.IsInputRedirected)
        {
            password = Console.In.ReadLine();
        }
        else
        {
            Console.Error.Write("Password: ");
            password = ReadHidden();
        }
        if (string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("Empty password.");
            return 1;
        }
        Console.Out.WriteLine(PasswordHasher.Hash(password));
        return 0;
    }

    static string ReadHidden()
    {
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                    sb.Length--;
                continue;
            }
            sb.Append(key.KeyChar);
        }
        Console.Error.WriteLine();
        return sb.ToString();
    }
}
