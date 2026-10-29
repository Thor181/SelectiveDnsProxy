using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using SelectiveDnsProxy;

internal static class Regression
{
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    public static async Task Main()
    {
        var query = Convert.FromHexString("123401000001000000000000076578616D706C6503636F6D0000010001");
        Check(DnsWire.TryReadQuestion(query, out var question), "Query parsing");
        var response = DnsWire.BuildAddressResponse(query, question, IPAddress.Loopback);
        Check(DnsWire.IsResponseTo(query, response), "Valid DNS response rejected");
        foreach (var offset in new[] { 0, 2, 5, 13, 25, 27 })
        {
            var bad = response.ToArray();
            bad[offset] ^= 0x80;
            Check(!DnsWire.IsResponseTo(query, bad), $"Invalid DNS response accepted at {offset}");
        }
        Check(!DnsWire.IsResponseTo(query, [1, 2]), "Short DNS response accepted");
        Console.WriteLine("PASS DNS response validation");

        using (var lifetime = new CancellationTokenSource())
        {
            var failure = new IOException("expected failure");
            try
            {
                await ServiceTasks.RunAsync([Task.FromException(failure), Task.Delay(-1, lifetime.Token)], lifetime)
                    .WaitAsync(TimeSpan.FromSeconds(3));
                throw new Exception("Service failure swallowed");
            }
            catch (IOException ex) { Check(ReferenceEquals(ex, failure), "Original failure lost"); }
            Check(lifetime.IsCancellationRequested, "Sibling service not cancelled");
        }
        Console.WriteLine("PASS service failure cancels siblings");

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = deadline.Token;
        using var backend = new TcpListener(IPAddress.Loopback, 0);
        backend.Start();
        var routePort = FreePort();
        var config = new DnsProxyConfig
        {
            HttpPort = routePort, HttpsPort = 0,
            Routes = [new HostRoute { Host = "example.com", Target = $"127.0.0.1:{((IPEndPoint)backend.LocalEndpoint).Port}" }]
        };
        config.Validate();
        using var routerLifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        var router = new TcpRouter(config).RunAsync(routerLifetime.Token);
        try
        {
            var hello = ClientHello();
            var whole = Record(hello);
            Check(TcpRouter.ParseSni(whole) == "example.com", "SNI parser");
            Check(TcpRouter.ParseSni(whole[..^1]) is null, "Truncated TLS accepted");
            // Split inside the handshake header, before SNI, and inside the hostname.
            foreach (var split in new[] { 2, 40, hello.Length - 3 })
            {
                var wire = Record(hello[..split]).Concat(Record(hello[split..])).ToArray();
                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, routePort, token);
                var clientStream = client.GetStream();
                var accepted = backend.AcceptTcpClientAsync(token);
                await clientStream.WriteAsync(wire, token);
                using var upstream = await accepted;
                var upstreamStream = upstream.GetStream();
                var received = new byte[wire.Length];
                await upstreamStream.ReadExactlyAsync(received, token);
                Check(received.SequenceEqual(wire), "TLS bytes changed");
                client.Client.Shutdown(SocketShutdown.Send);
                Check(await upstreamStream.ReadAsync(new byte[1], token) == 0, "Half-close missing");
                await upstreamStream.WriteAsync(new byte[] { 42 }, token);
                upstream.Client.Shutdown(SocketShutdown.Send);
                var reply = new byte[1];
                await clientStream.ReadExactlyAsync(reply, token);
                Check(reply[0] == 42, "Reply after half-close lost");
                Check(await clientStream.ReadAsync(reply, token) == 0, "Reply EOF missing");
            }
            Console.WriteLine("PASS fragmented TLS and half-close round trip");

            // One port is free and another occupied: all listeners must stop on failure.
            var otherPort = FreePort();
            var conflicting = new DnsProxyConfig
            {
                HttpPort = otherPort, HttpsPort = routePort,
                Routes = [new HostRoute { Host = "example.com", Target = "127.0.0.1:1" }]
            };
            conflicting.Validate();
            try
            {
                await new TcpRouter(conflicting).RunAsync(token).WaitAsync(TimeSpan.FromSeconds(3));
                throw new Exception("Occupied port accepted");
            }
            catch (SocketException) { }
            using var probe = new TcpListener(IPAddress.Loopback, otherPort);
            probe.Start();
            Console.WriteLine("PASS occupied router port fails and releases sibling listener");
        }
        finally
        {
            routerLifetime.Cancel();
            try { await router; } catch (OperationCanceledException) { }
        }

        using var transfer = new CancellationTokenSource();
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        var pump = typeof(TcpRouter).GetMethod("PumpAsync", BindingFlags.NonPublic | BindingFlags.Static)!;
        var failing = (Task)pump.Invoke(null, [new FailingStream(), Stream.Null, socket, transfer])!;
        try { await failing; throw new Exception("Pump failure swallowed"); }
        catch (IOException) { }
        Check(transfer.IsCancellationRequested, "Failed pump did not cancel sibling");
        Console.WriteLine("PASS transfer error cancels sibling pump");
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static byte[] Record(byte[] payload)
    {
        var record = new byte[5 + payload.Length];
        record[0] = 0x16; record[1] = 3; record[2] = 3;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), (ushort)payload.Length);
        payload.CopyTo(record, 5);
        return record;
    }

    private static byte[] ClientHello()
    {
        var name = Encoding.ASCII.GetBytes("example.com");
        using var stream = new MemoryStream();
        stream.Write(new byte[4]);
        stream.Write(new byte[] { 3, 3 });
        stream.Write(new byte[32]);
        stream.Write(new byte[] { 0, 0, 2, 0x13, 1, 1, 0 });
        void U16(int value) { stream.WriteByte((byte)(value >> 8)); stream.WriteByte((byte)value); }
        U16(9 + name.Length); U16(0); U16(5 + name.Length);
        U16(3 + name.Length); stream.WriteByte(0); U16(name.Length); stream.Write(name);
        var hello = stream.ToArray();
        hello[0] = 1; hello[3] = (byte)(hello.Length - 4);
        return hello;
    }

    private sealed class FailingStream : MemoryStream
    {
        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken) =>
            Task.FromException(new IOException("simulated connection reset"));
    }
}

