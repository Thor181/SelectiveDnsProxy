using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SelectiveDnsProxy;

/// <summary>
/// Маршрутизация TCP по имени хоста на всех портах из маршрутов. Протокол определяется по первому байту:
/// TLS — хост из SNI в ClientHello, иначе HTTP — хост из заголовка Host.
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

    public async Task RunAsync(CancellationToken token)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        await ServiceTasks.RunAsync(_config.RouterPorts.Select(port => ListenAsync(port, lifetime.Token)), lifetime);
    }

    private async Task ListenAsync(int port, CancellationToken token)
    {
        var listener = new TcpListener(_listenIp, port);
        try { listener.Start(); }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"Router: не удалось занять {_listenIp}:{port} ({ex.SocketErrorCode}).");
            throw;
        }
        Console.WriteLine($"Router listening on {_listenIp}:{port}");
        try
        {
            while (!token.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(token); }
                catch (OperationCanceledException) { break; }
                _ = HandleAsync(client, port, token);
            }
        }
        finally { listener.Stop(); }
    }

    private async Task HandleAsync(TcpClient client, int port, CancellationToken token)
    {
        var label = $":{port}";
        using (client)
        using (var upstream = new TcpClient { NoDelay = true })
        {
            try
            {
                client.NoDelay = true;
                var clientStream = client.GetStream();

                string? host;
                bool tls;
                byte[] buffered;
                using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    handshake.CancelAfter(_config.TimeoutMs * 4);
                    var first = new byte[1];
                    await clientStream.ReadExactlyAsync(first, handshake.Token);
                    tls = first[0] == 0x16; // TLS handshake record
                    (host, buffered) = tls
                        ? await ReadTlsSniAsync(clientStream, first[0], handshake.Token)
                        : await ReadHttpHostAsync(clientStream, first[0], handshake.Token);
                }
                label = $"{(tls ? "HTTPS" : "HTTP")} :{port}";

                var route = host is null ? null : _config.FindRoute(host, port);
                if (route is null)
                {
                    Console.Error.WriteLine($"{label} {client.Client.RemoteEndPoint}: нет маршрута для '{host}'");
                    if (!tls) await WriteNotFoundAsync(clientStream, token);
                    return;
                }

                var targetPort = route.Ports[port].LocalPort;
                Console.WriteLine($"{label} {host} -> {route.TargetHost}:{targetPort}");
                using (var connect = CancellationTokenSource.CreateLinkedTokenSource(token))
                {
                    connect.CancelAfter(_config.TimeoutMs);
                    await upstream.ConnectAsync(route.TargetHost, targetPort, connect.Token);
                }

                var upstreamStream = upstream.GetStream();
                await upstreamStream.WriteAsync(buffered, token);
                using var transfer = CancellationTokenSource.CreateLinkedTokenSource(token);
                await Task.WhenAll(
                    PumpAsync(clientStream, upstreamStream, upstream.Client, transfer),
                    PumpAsync(upstreamStream, clientStream, client.Client, transfer));
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"{label} error: {ex.Message}");
            }
        }
    }

    private static async Task PumpAsync(Stream from, Stream to, Socket toSocket, CancellationTokenSource transfer)
    {
        try
        {
            await from.CopyToAsync(to, 81920, transfer.Token);
            toSocket.Shutdown(SocketShutdown.Send);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            transfer.Cancel();
            throw;
        }
    }

    private static async Task WriteNotFoundAsync(Stream stream, CancellationToken token)
    {
        var body = "No route for this host\n";
        var response = $"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), token);
    }

    private static async Task<(string?, byte[])> ReadHttpHostAsync(NetworkStream stream, byte first, CancellationToken token)
    {
        var buffer = new byte[MaxHeaderBytes];
        buffer[0] = first;
        var length = 1;
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

    private static async Task<(string?, byte[])> ReadTlsSniAsync(NetworkStream stream, byte first, CancellationToken token)
    {
        const int maxHelloBytes = 256 * 1024;
        using var wire = new MemoryStream();
        using var hello = new MemoryStream();
        var header = new byte[5];
        header[0] = first;
        var firstRecord = true;
        while (wire.Length < maxHelloBytes)
        {
            if (firstRecord) await stream.ReadExactlyAsync(header.AsMemory(1), token);
            else await stream.ReadExactlyAsync(header, token);
            firstRecord = false;
            var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
            if (header[0] != 0x16 || header[1] != 3 || length == 0 || length > 16384 ||
                wire.Length + 5 + length > maxHelloBytes)
                return (null, wire.ToArray());
            var payload = new byte[length];
            await stream.ReadExactlyAsync(payload, token);
            wire.Write(header);
            wire.Write(payload);
            hello.Write(payload);
            var data = hello.GetBuffer();
            if (hello.Length < 4) continue;
            var helloLength = 4 + (data[1] << 16 | data[2] << 8 | data[3]);
            if (data[0] != 1 || helloLength > maxHelloBytes) return (null, wire.ToArray());
            if (hello.Length >= helloLength)
                return (ParseClientHello(data.AsSpan(0, helloLength)), wire.ToArray());
        }
        return (null, wire.ToArray());
    }
    /// <summary>Извлекает server_name из TLS ClientHello (запись целиком, включая 5-байтный заголовок).</summary>
    internal static string? ParseSni(byte[] record)
    {
        if (record.Length < 5 || record[0] != 0x16) return null;
        var length = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(3, 2));
        return length == record.Length - 5 ? ParseClientHello(record.AsSpan(5)) : null;
    }

    private static string? ParseClientHello(ReadOnlySpan<byte> hello)
    {
        try
        {
            if (hello.Length < 39 || hello[0] != 1) return null;
            var length = 4 + (hello[1] << 16 | hello[2] << 8 | hello[3]);
            if (length != hello.Length) return null;
            var p = 38; // handshake header, version, random
            p += 1 + hello[p];
            var cipherLength = BinaryPrimitives.ReadUInt16BigEndian(hello.Slice(p, 2));
            p += 2 + cipherLength;
            p += 1 + hello[p];
            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(hello.Slice(p, 2));
            p += 2;
            if (p + extensionsLength != hello.Length) return null;
            string? host = null;
            while (p < hello.Length)
            {
                var type = BinaryPrimitives.ReadUInt16BigEndian(hello.Slice(p, 2));
                var size = BinaryPrimitives.ReadUInt16BigEndian(hello.Slice(p + 2, 2));
                p += 4;
                var extension = hello.Slice(p, size);
                p += size;
                if (type != 0) continue;
                if (host is not null || extension.Length < 2 ||
                    BinaryPrimitives.ReadUInt16BigEndian(extension) != extension.Length - 2) return null;
                var n = 2;
                while (n < extension.Length)
                {
                    var nameType = extension[n];
                    var nameLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(n + 1, 2));
                    n += 3;
                    var name = extension.Slice(n, nameLength);
                    n += nameLength;
                    if (nameType != 0) continue;
                    if (host is not null || nameLength == 0) return null;
                    foreach (var b in name)
                        if (b <= 32 || b >= 127) return null;
                    host = Encoding.ASCII.GetString(name).ToLowerInvariant();
                }
            }
            return host;
        }
        catch (ArgumentOutOfRangeException) { return null; }
        catch (IndexOutOfRangeException) { return null; }
    }
}
