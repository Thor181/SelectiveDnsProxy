using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SelectiveDnsProxy;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true
    };

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        var configPath = args.Length > 0 ? args[0] : Path.Combine(Environment.CurrentDirectory, "dnsproxy.json");
        if (!File.Exists(configPath))
        {
            var template = DnsProxyConfig.CreateDefault();
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(template, JsonOptions));
            Console.WriteLine($"Создан шаблон конфигурации: {configPath}");
            Console.WriteLine("Отредактируйте файл и запустите программу повторно.");
            return;
        }

        var config = JsonSerializer.Deserialize<DnsProxyConfig>(await File.ReadAllTextAsync(configPath), JsonOptions)
                     ?? throw new InvalidOperationException("Не удалось прочитать конфигурацию.");
        config.Validate();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        var server = new DnsProxyServer(config);
        Console.WriteLine($"Selective DNS Proxy listening on {config.ListenAddress}:{config.Port}");
        Console.WriteLine($"Default upstream: {string.Join(", ", config.DefaultUpstream)}");
        Console.WriteLine("Нажмите Ctrl+C для остановки.");
        var tasks = new List<Task> { server.RunAsync(cts.Token) };
        if (config.Routes.Count > 0) tasks.Add(new TcpRouter(config).RunAsync(cts.Token));
        if (config.Routes.Any(r => r.SshHost is not null)) tasks.Add(new SshTunnels(config).RunAsync(cts.Token));
        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) { }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            Console.Error.WriteLine($"Порт {config.Port} уже занят. Запустите от администратора и проверьте другие DNS-службы.");
            Environment.ExitCode = 2;
        }
    }
}

internal sealed class DnsProxyConfig
{
    public string ListenAddress { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 53;
    public int TimeoutMs { get; set; } = 2500;
    public List<string> DefaultUpstream { get; set; } = ["1.1.1.1", "8.8.8.8"];
    public List<DnsRule> Rules { get; set; } = [];
    public string RouteAddress { get; set; } = "127.0.0.1";
    public int HttpPort { get; set; } = 80;
    public int HttpsPort { get; set; } = 443;
    public List<HostRoute> Routes { get; set; } = [];

    public HostRoute? FindRoute(string host)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        return Routes
            .Where(r => host == r.Host || (r.IncludeSubdomains && host.EndsWith("." + r.Host)))
            .OrderByDescending(r => r.Host.Length)
            .FirstOrDefault();
    }

    public static DnsProxyConfig CreateDefault() => new()
    {
        Rules =
        [
            new DnsRule { Domain = "example.com", Address = "203.0.113.10", IncludeSubdomains = false },
            new DnsRule { Domain = "internal.example.com", Upstream = "192.168.1.1", IncludeSubdomains = true }
        ]
    };

    public void Validate()
    {
        if (!IPAddress.TryParse(ListenAddress, out _)) throw new InvalidOperationException("ListenAddress должен быть IP-адресом.");
        if (Port is < 1 or > 65535) throw new InvalidOperationException("Port должен быть в диапазоне 1..65535.");
        if (TimeoutMs is < 100 or > 30000) throw new InvalidOperationException("TimeoutMs должен быть в диапазоне 100..30000.");
        if (DefaultUpstream.Count == 0 || DefaultUpstream.Any(x => !IPAddress.TryParse(x, out _)))
            throw new InvalidOperationException("DefaultUpstream должен содержать хотя бы один корректный IP DNS-сервера.");
        if (!IPAddress.TryParse(RouteAddress, out _)) throw new InvalidOperationException("RouteAddress должен быть IP-адресом.");
        if (HttpPort is < 0 or > 65535 || HttpsPort is < 0 or > 65535)
            throw new InvalidOperationException("HttpPort/HttpsPort должны быть в диапазоне 0..65535 (0 — отключено).");
        foreach (var route in Routes)
        {
            route.Host = route.Host.Trim().TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(route.Host) || route.Host.Contains('/') || route.Host.Contains(' '))
                throw new InvalidOperationException($"Некорректный Host в маршруте: '{route.Host}'.");
            route.ParseTarget();
        }
        foreach (var rule in Rules)
        {
            rule.Domain = rule.Domain.Trim().TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(rule.Domain) || rule.Domain.Contains('/') || rule.Domain.Contains(' '))
                throw new InvalidOperationException($"Некорректный домен в правиле: '{rule.Domain}'.");
            if (string.IsNullOrWhiteSpace(rule.Address) == string.IsNullOrWhiteSpace(rule.Upstream))
                throw new InvalidOperationException($"Правило '{rule.Domain}' должно задавать ровно одно из полей Address или Upstream.");
            if (rule.Address is not null && !IPAddress.TryParse(rule.Address, out _))
                throw new InvalidOperationException($"Некорректный IP Address в правиле '{rule.Domain}'.");
            if (rule.Upstream is not null && !IPAddress.TryParse(rule.Upstream, out _))
                throw new InvalidOperationException($"Некорректный IP Upstream в правиле '{rule.Domain}'.");
        }
    }
}

internal sealed class HostRoute
{
    public string Host { get; set; } = "";
    public bool IncludeSubdomains { get; set; }
    /// <summary>
    /// Локальный адрес "127.0.0.1:5001" без SSH-туннеля: на него пересылаются и HTTP, и HTTPS.
    /// При заданном SshHost не указывается — локальные порты туннеля выбираются автоматически.
    /// </summary>
    public string? Target { get; set; }

    /// <summary>SSH-хост для автоматического туннеля ("user@host" или алиас из ssh_config). Пусто — туннель не поднимается.</summary>
    public string? SshHost { get; set; }
    public int? SshPort { get; set; }
    public string? SshKey { get; set; }
    /// <summary>Хост, к которому SSH-сервер подключается по 80/443. По умолчанию — сам Host.</summary>
    public string? SshRemoteHost { get; set; }

    [JsonIgnore] public string RemoteHost => string.IsNullOrWhiteSpace(SshRemoteHost) ? Host : SshRemoteHost;
    [JsonIgnore] public string TargetHost { get; private set; } = "127.0.0.1";
    [JsonIgnore] public int HttpTargetPort { get; private set; }
    [JsonIgnore] public int HttpsTargetPort { get; private set; }

    public void ParseTarget()
    {
        if (string.IsNullOrWhiteSpace(SshHost)) SshHost = null;
        if (SshHost is not null && (SshHost.StartsWith('-') || SshHost.Contains(' ')))
            throw new InvalidOperationException($"Маршрут '{Host}': некорректный SshHost.");
        if (SshPort is < 1 or > 65535) throw new InvalidOperationException($"Маршрут '{Host}': некорректный SshPort.");
        if (!string.IsNullOrWhiteSpace(SshRemoteHost) &&
            (SshRemoteHost.StartsWith('-') || SshRemoteHost.Contains(' ') || SshRemoteHost.Contains(':')))
            throw new InvalidOperationException($"Маршрут '{Host}': SshRemoteHost должен быть именем хоста без порта.");

        if (SshHost is not null)
        {
            if (!string.IsNullOrWhiteSpace(Target))
                throw new InvalidOperationException($"Маршрут '{Host}': при заданном SshHost поле Target не используется — удалите его.");
            HttpTargetPort = GetFreePort();
            HttpsTargetPort = GetFreePort();
            return;
        }

        var colon = Target?.LastIndexOf(':') ?? -1;
        if (colon <= 0 || !int.TryParse(Target![(colon + 1)..], out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException($"Маршрут '{Host}': нужен SshHost либо Target в формате host:port.");
        TargetHost = Target[..colon];
        HttpTargetPort = HttpsTargetPort = port;
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try { return ((IPEndPoint)listener.LocalEndpoint).Port; }
        finally { listener.Stop(); }
    }
}

internal sealed class DnsRule
{
    public string Domain { get; set; } = "";
    public bool IncludeSubdomains { get; set; }
    public string? Address { get; set; }
    public string? Upstream { get; set; }
}

internal sealed class DnsProxyServer
{
    private readonly DnsProxyConfig _config;
    private readonly IPAddress _listenIp;
    private readonly List<IPAddress> _defaultUpstreams;

    public DnsProxyServer(DnsProxyConfig config)
    {
        _config = config;
        _listenIp = IPAddress.Parse(config.ListenAddress);
        _defaultUpstreams = config.DefaultUpstream.Select(IPAddress.Parse).ToList();
    }

    public async Task RunAsync(CancellationToken token)
    {
        using var udp = new UdpClient(new IPEndPoint(_listenIp, _config.Port));
        var tcpListener = new TcpListener(_listenIp, _config.Port);
        tcpListener.Start();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token);
        var udpTask = RunUdpAsync(udp, linked.Token);
        var tcpTask = RunTcpAsync(tcpListener, linked.Token);
        try { await Task.WhenAll(udpTask, tcpTask); }
        finally { linked.Cancel(); tcpListener.Stop(); }
    }

    private async Task RunUdpAsync(UdpClient listener, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try { received = await listener.ReceiveAsync(token); }
            catch (OperationCanceledException) { break; }
            _ = HandleUdpAsync(listener, received, token);
        }
    }

    private async Task HandleUdpAsync(UdpClient listener, UdpReceiveResult received, CancellationToken token)
    {
        try
        {
            var query = received.Buffer;
            if (!DnsWire.TryReadQuestion(query, out var question)) return;
            Console.WriteLine($"UDP {received.RemoteEndPoint} {question.Name} type={question.Type}");
            var response = await ResolveAsync(query, question, tcp: false, token);
            if (response is { Length: > 0 }) await listener.SendAsync(response, received.RemoteEndPoint, token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine($"UDP error: {ex.Message}");
        }
    }

    private async Task RunTcpAsync(TcpListener listener, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(token); }
            catch (OperationCanceledException) { break; }
            _ = HandleTcpClientAsync(client, token);
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken token)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                var stream = client.GetStream();
                var prefix = new byte[2];
                await stream.ReadExactlyAsync(prefix, token);
                var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
                if (length < 12) return;
                var query = new byte[length];
                await stream.ReadExactlyAsync(query, token);
                if (!DnsWire.TryReadQuestion(query, out var question)) return;
                Console.WriteLine($"TCP {client.Client.RemoteEndPoint} {question.Name} type={question.Type}");
                var response = await ResolveAsync(query, question, tcp: true, token);
                if (response is null || response.Length > ushort.MaxValue) return;
                var outPrefix = new byte[2];
                BinaryPrimitives.WriteUInt16BigEndian(outPrefix, (ushort)response.Length);
                await stream.WriteAsync(outPrefix, token);
                await stream.WriteAsync(response, token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"TCP error: {ex.Message}");
            }
        }
    }

    private async Task<byte[]?> ResolveAsync(byte[] query, DnsQuestion question, bool tcp, CancellationToken token)
    {
        var rule = _config.Rules
            .Where(r => question.Name.Equals(r.Domain, StringComparison.OrdinalIgnoreCase) ||
                        (r.IncludeSubdomains && question.Name.EndsWith("." + r.Domain, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(r => r.Domain.Length)
            .FirstOrDefault();

        if (rule?.Address is not null && question.Type is 1 or 28)
        {
            var ip = IPAddress.Parse(rule.Address);
            return DnsWire.BuildAddressResponse(query, question, ip);
        }

        if (rule is null && question.Type is 1 or 28 && _config.FindRoute(question.Name) is not null)
            return DnsWire.BuildAddressResponse(query, question, IPAddress.Parse(_config.RouteAddress));

        IReadOnlyList<IPAddress> upstreams = rule?.Upstream is not null ? new[] { IPAddress.Parse(rule.Upstream) } : _defaultUpstreams;
        foreach (var upstream in upstreams)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(_config.TimeoutMs);
                return tcp
                    ? await ForwardTcpAsync(upstream, query, timeout.Token)
                    : await ForwardUdpAsync(upstream, query, timeout.Token);
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                if (token.IsCancellationRequested) throw;
                Console.Error.WriteLine($"Upstream {upstream} failed: {ex.Message}");
            }
        }
        return DnsWire.BuildServFail(query);
    }

    private async Task<byte[]> ForwardUdpAsync(IPAddress upstream, byte[] query, CancellationToken token)
    {
        using var client = new UdpClient(upstream.AddressFamily);
        await client.SendAsync(query, new IPEndPoint(upstream, 53), token);
        var result = await client.ReceiveAsync(token);
        return result.Buffer;
    }

    private static async Task<byte[]> ForwardTcpAsync(IPAddress upstream, byte[] query, CancellationToken token)
    {
        using var client = new TcpClient(upstream.AddressFamily);
        await client.ConnectAsync(upstream, 53, token);
        var stream = client.GetStream();
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, checked((ushort)query.Length));
        await stream.WriteAsync(prefix, token);
        await stream.WriteAsync(query, token);
        await stream.ReadExactlyAsync(prefix, token);
        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        var response = new byte[length];
        await stream.ReadExactlyAsync(response, token);
        return response;
    }
}

internal sealed record DnsQuestion(string Name, ushort Type, ushort Class, int EndOffset);

internal static class DnsWire
{
    public static bool TryReadQuestion(byte[] packet, out DnsQuestion question)
    {
        question = new DnsQuestion("", 0, 0, 0);
        if (packet.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2)) == 0) return false;
        var labels = new List<string>();
        var offset = 12;
        while (offset < packet.Length)
        {
            var size = packet[offset++];
            if (size == 0) break;
            // Queries should contain an uncompressed QNAME. Reject compression and malformed labels.
            if ((size & 0xC0) != 0 || size > 63 || offset + size > packet.Length) return false;
            labels.Add(System.Text.Encoding.ASCII.GetString(packet, offset, size));
            offset += size;
            if (labels.Count > 127) return false;
        }
        if (offset + 4 > packet.Length) return false;
        var type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
        var @class = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2));
        offset += 4;
        question = new DnsQuestion(string.Join('.', labels).TrimEnd('.').ToLowerInvariant(), type, @class, offset);
        return true;
    }

    public static byte[] BuildAddressResponse(byte[] query, DnsQuestion question, IPAddress address)
    {
        var isA = question.Type == 1 && address.AddressFamily == AddressFamily.InterNetwork;
        var isAaaa = question.Type == 28 && address.AddressFamily == AddressFamily.InterNetworkV6;
        var hasAnswer = isA || isAaaa;
        var answerLength = hasAnswer ? 12 + address.GetAddressBytes().Length : 0;
        var result = new byte[12 + (question.EndOffset - 12) + answerLength];
        query.AsSpan(0, 2).CopyTo(result.AsSpan(0, 2));
        var requestFlags = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2));
        var flags = (ushort)(0x8000 | 0x0080 | (requestFlags & 0x0100)); // QR, RA, copy RD
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6, 2), hasAnswer ? (ushort)1 : (ushort)0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10, 2), 0);
        query.AsSpan(12, question.EndOffset - 12).CopyTo(result.AsSpan(12));
        if (hasAnswer)
        {
            var p = question.EndOffset;
            result[p++] = 0xC0; result[p++] = 0x0C;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(p, 2), question.Type); p += 2;
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(p, 2), question.Class); p += 2;
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(p, 4), 60); p += 4;
            var bytes = address.GetAddressBytes();
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(p, 2), (ushort)bytes.Length); p += 2;
            bytes.CopyTo(result.AsSpan(p));
        }
        return result;
    }

    public static byte[] BuildServFail(byte[] query)
    {
        var response = new byte[12];
        query.AsSpan(0, Math.Min(2, query.Length)).CopyTo(response);
        var requestFlags = query.Length >= 4 ? BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2)) : (ushort)0;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)(0x8000 | 0x0080 | (requestFlags & 0x0100) | 0x0002));
        return response;
    }
}
