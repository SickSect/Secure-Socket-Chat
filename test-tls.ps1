$host = "localhost"
$port = 5000

# Грузим сертификат сервера как доверенный
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("certs\server.crt")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedRoot", "CurrentUser")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

try {
    $tcp = New-Object System.Net.Sockets.TcpClient($host, $port)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {$true})
    $ssl.AuthenticateAsClient($host)

    Write-Host "TLS OK!"
    Write-Host "Protocol: $($ssl.SslProtocol)"
    Write-Host "Cipher: $($ssl.CipherAlgorithm)"
    Write-Host "Server cert: $($ssl.RemoteCertificate.Subject)"

    $ssl.Close()
    $tcp.Close()
} catch {
    Write-Host "TLS FAILED: $_"
}