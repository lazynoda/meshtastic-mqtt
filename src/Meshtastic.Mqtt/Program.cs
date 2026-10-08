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
        var options = new MqttServerOptionsBuilder()
            .WithDefaultEndpoint()
            .WithDefaultEndpointPort(config.Listener.Port)
            .Build();
        // MQTTnet opens one IPv4 and one IPv6 socket; bind only the family of the configured address.
        var endpoint = options.DefaultEndpointOptions;
        if (config.BindAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            endpoint.BoundInterNetworkAddress = config.BindAddress;
            endpoint.BoundInterNetworkV6Address = System.Net.IPAddress.None;
        }
        else
        {
            endpoint.BoundInterNetworkAddress = System.Net.IPAddress.None;
            endpoint.BoundInterNetworkV6Address = config.BindAddress;
        }

        using var server = new MqttServerFactory().CreateMqttServer(options);
        new BrokerHooks(config, logger).Attach(server);

        var stop = new TaskCompletionSource();
        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; stop.TrySetResult(); });
        using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; stop.TrySetResult(); });

        try
        {
            await server.StartAsync();
        }
        catch (Exception ex)
        {
            logger.Fatal("Cannot start the MQTT listener on {Address}:{Port}: {Error}", config.BindAddress, config.Listener.Port, ex.Message);
            return 1;
        }

        logger.Information("Listening on {Address}:{Port} (plain MQTT). {Users} user(s), {Channels} channel key(s), drop_undecryptable={DropUndecryptable}, drop_pki={DropPki}",
            config.BindAddress, config.Listener.Port, config.Users!.Count, config.ChannelKeyMap.Count, config.DropUndecryptable, config.DropPki);

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
