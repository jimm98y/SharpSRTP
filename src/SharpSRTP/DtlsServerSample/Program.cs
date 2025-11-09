
using DtlsSample;
using DtlsServerSample;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Tests;
using System;
using System.Threading;

var serverCertificate = CertificateUtils.GenerateServerCertificate(
    "WebRTC", 
    DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30)); 

MockDtlsServer server = new MockDtlsServer();
DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

UdpDatagramTransport serverTransport = new UdpDatagramTransport();
serverTransport.Listen("127.0.0.1:8888");
ServerTask serverTask = new ServerTask(serverProtocol, server, serverTransport);

Thread serverThread = new Thread(serverTask.Run);
serverThread.Start();
