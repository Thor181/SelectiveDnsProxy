using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SelectiveDnsProxy;

/// <summary>
/// Маршрутизация TCP по имени хоста: HTTP (порт 80) — по заголовку Host, HTTPS (порт 443) — по SNI из ClientHello.
/// TLS не терминируется, трафик пересылается как есть на локальный порт туннеля.
/// </summary>
internal sealed class TcpRouter
{
    private const int MaxHeaderBytes = 16 * 1024;

    private readonly DnsProxyConfig _config;
    private readonly IPAddress _listenIp;

    public TcpRouter(DnsProxyConfig config)
    {
        _config = config;
        _listenIp = IPAddress.Parse(config.ListenAddress);
    }

    public Task RunAsync(CancellationToken token)
    {
        var tasks = new List<Task>();
        if (_config.HttpPort > 0) tasks.Add(ListenAsync(_config.HttpPort, "HTTP", ReadHttpHostAsync, token));
        if (_config.HttpsPort > 0) tasks.Add(ListenAsync(_config.HttpsPort, "HTTPS", ReadTlsSniAsync, token));
        return Task.WhenAll(tasks);
    }

    private delegate Task<(string? Host, byte[] Buffered)> HostReader(NetworkStream stream, CancellationToken token);

    private async Task ListenAsync(int port, string label, HostReader readHost, CancellationToken token)
    {
        var listener = new TcpListener(_listenIp, port);
        try { listener.Start(); }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"{label} router: не удалось занять {_listenIp}:{port} ({ex.SocketErrorCode}). Порт занят другой службой? Роутер {label} отключён.");
            return;
        }
        Console.WriteLine($"{label} router listening on {_listenIp}:{port}");
        try
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(token); }
                catch (OperationCanceledException) { break; }
                _ = HandleAsync(client, label, readHost, token);
            }
        }
        finally { listener.Stop(); }
    }

    private async Task HandleAsync(TcpClient client, string label, HostReader readHost, CancellationToken token)
    {
        using (client)
        using (var upstream = new TcpClient { NoDelay = true })
        {
            try
            {
                client.NoDelay = true;
                var clientStream = client.GetStream();

                string? host;
                byte[] buffered;
                using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    handshake.CancelAfter(_config.TimeoutMs * 4);
                    (host, buffered) = await readHost(clientStream, handshake.Token);
                }

                var route = host is null ? null : _config.FindRoute(host);
                if (route is null)
                {
                    Console.Error.WriteLine($"{label} {client.Client.RemoteEndPoint}: нет маршрута для '{host}'");
                    if (label == "HTTP") await WriteNotFoundAsync(clientStream, token);
                    return;
                }

                var targetPort = label == "HTTP" ? route.HttpTargetPort : route.HttpsTargetPort;
                Console.WriteLine($"{label} {host} -> {route.TargetHost}:{targetPort}");
                using (var connect = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    connect.CancelAfter(_config.TimeoutMs);
                    await upstream.ConnectAsync(route.TargetHost, targetPort, connect.Token);
                }

                var upstreamStream = upstream.GetStream();
                await upstreamStream.WriteAsync(buffered, token);
                await Task.WhenAll(
                    PumpAsync(clientStream, upstreamStream, upstream.Client, token),
                    PumpAsync(upstreamStream, clientStream, client.Client, token));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"{label} error: {ex.Message}");
            }
        }
    }

    private static async Task PumpAsync(Stream from, Stream to, Socket toSocket, CancellationToken token)
    {
        try
        {
            await from.CopyToAsync(to, 81920, token);
            toSocket.Shutdown(SocketShutdown.Send);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException) { }
    }

    private static async Task WriteNotFoundAsync(Stream stream, CancellationToken token)
    {
        var body = "No route for this host\n";
        var response = $"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), token);
    }

    private static async Task<(string?, byte[])> ReadHttpHostAsync(NetworkStream stream, CancellationToken token)
    {
        var buffer = new byte[MaxHeaderBytes];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), token);
            if (read == 0) break;
            length += read;
            var text = Encoding.ASCII.GetString(buffer, 0, length);
            var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end < 0) continue;

            foreach (var line in text[..end].Split("\r\n").Skip(1))
            {
                if (!line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) continue;
                var value = line[5..].Trim();
                // Отрезаем порт: host:8080, [::1]:8080 не поддерживаем (маршрутизация по имени).
                var colon = value.LastIndexOf(':');
                if (colon > 0 && !value.EndsWith(']')) value = value[..colon];
                return (value.ToLowerInvariant(), buffer[..length]);
            }
            return (null, buffer[..length]);
        }
        return (null, buffer[..length]);
    }

    private static async Task<(string?, byte[])> ReadTlsSniAsync(NetworkStream stream, CancellationToken token)
    {
        var header = new byte[5];
        await stream.ReadExactlyAsync(header, token);
        if (header[0] != 0x16) return (null, header);

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
        var buffer = new byte[5 + recordLength];
        header.CopyTo(buffer, 0);
        await stream.ReadExactlyAsync(buffer.AsMemory(5), token);
        return (ParseSni(buffer), buffer);
    }

    /// <summary>Извлекает server_name из TLS ClientHello (запись целиком, включая 5-байтный заголовок).</summary>
    internal static string? ParseSni(byte[] record)
    {
        try
        {
            var p = 5;
            if (record.Length < 43 || record[p] != 0x01) return null; // handshake type = ClientHello
            p += 4 + 2 + 32;                                         // handshake header, version, random
            p += 1 + record[p];                                      // session id
            p += 2 + BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(p, 2)); // cipher suites
            p += 1 + record[p];                                      // compression methods
            var extensionsEnd = p + 2 + BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(p, 2));
            p += 2;
            while (p + 4 <= extensionsEnd && p + 4 <= record.Length)
            {
                var type = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(p, 2));
                var size = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(p + 2, 2));
                p += 4;
                if (type == 0) // server_name
                {
                    // list length (2), name type (1), name length (2), name
                    var nameLength = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(p + 3, 2));
                    return Encoding.ASCII.GetString(record, p + 5, nameLength).ToLowerInvariant();
                }
                p += size;
            }
        }
        catch (ArgumentOutOfRangeException) { }
        catch (IndexOutOfRangeException) { }
        return null;
    }
}
