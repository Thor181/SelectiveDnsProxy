using System.Diagnostics;

namespace SelectiveDnsProxy;

/// <summary>
/// Поднимает и поддерживает SSH-туннели (системный ssh, -L) для маршрутов с заданным SshHost.
/// При падении процесса перезапускает его с растущей паузой.
/// </summary>
internal sealed class SshTunnels
{
    private readonly DnsProxyConfig _config;

    public SshTunnels(DnsProxyConfig config) => _config = config;

    public Task RunAsync(CancellationToken token) =>
        Task.WhenAll(_config.Routes.Where(r => !string.IsNullOrWhiteSpace(r.SshHost)).Select(r => KeepAliveAsync(r, token)));

    private static async Task KeepAliveAsync(HostRoute route, CancellationToken token)
    {
        var delay = TimeSpan.FromSeconds(1);
        while (!token.IsCancellationRequested)
        {
            var started = DateTime.UtcNow;
            try
            {
                using var process = Process.Start(BuildStartInfo(route))
                                    ?? throw new InvalidOperationException("ssh не запустился.");
                Console.WriteLine($"SSH {route.Host}: туннель через {route.SshHost} -> {route.RemoteHost} (80 -> :{route.HttpTargetPort}, 443 -> :{route.HttpsTargetPort})");
                process.ErrorDataReceived += (_, e) => { if (e.Data is not null) Console.Error.WriteLine($"SSH {route.Host}: {e.Data}"); };
                process.BeginErrorReadLine();
                try { await process.WaitForExitAsync(token); }
                catch (OperationCanceledException)
                {
                    try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                    return;
                }
                Console.Error.WriteLine($"SSH {route.Host}: ssh завершился с кодом {process.ExitCode}");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"SSH {route.Host}: {ex.Message}");
            }

            // Если туннель продержался больше минуты — считаем запуск удачным и сбрасываем паузу.
            delay = DateTime.UtcNow - started > TimeSpan.FromMinutes(1)
                ? TimeSpan.FromSeconds(1)
                : TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 60));
            Console.Error.WriteLine($"SSH {route.Host}: перезапуск через {delay.TotalSeconds:0} c");
            try { await Task.Delay(delay, token); }
            catch (OperationCanceledException) { return; }
        }
    }

    private static ProcessStartInfo BuildStartInfo(HostRoute route)
    {
        var info = new ProcessStartInfo("ssh")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        foreach (var arg in new[]
                 {
                     "-N", "-T",
                     "-o", "ExitOnForwardFailure=yes",
                     "-o", "ServerAliveInterval=30",
                     "-o", "ServerAliveCountMax=3",
                     "-o", "BatchMode=yes",
                     "-o", "StrictHostKeyChecking=accept-new"
                 })
            info.ArgumentList.Add(arg);
        if (route.SshPort is { } port) { info.ArgumentList.Add("-p"); info.ArgumentList.Add(port.ToString()); }
        if (!string.IsNullOrWhiteSpace(route.SshKey)) { info.ArgumentList.Add("-i"); info.ArgumentList.Add(route.SshKey); }
        info.ArgumentList.Add("-L");
        info.ArgumentList.Add($"{route.TargetHost}:{route.HttpTargetPort}:{route.RemoteHost}:80");
        info.ArgumentList.Add("-L");
        info.ArgumentList.Add($"{route.TargetHost}:{route.HttpsTargetPort}:{route.RemoteHost}:443");
        info.ArgumentList.Add(route.SshHost!);
        return info;
    }
}
