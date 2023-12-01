using System;
using System.Net;
using SharpPcap;

namespace HTTP
{
    public class HTTPSniffer
    {
        public static void Main()
        {
            // Print SharpPcap version
            var ver = Pcap.SharpPcapVersion;
            Console.WriteLine("SharpPcap {0}, Example5.PcapFilter.cs\n", ver);

            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Scan the list printing every entry
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1}", i, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            using var device = devices[i];

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            //Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            string filter = "tcp dst port 80 or tcp src port 80";
            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine
                ("-- The following filter will be applied: \"{0}\"",
                filter);
            Console.WriteLine
                ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                device.Description);

            // Start capture packets
            device.Capture();

        }

        /// <summary>
        /// Prints the time and length of each received packet
        /// </summary>
        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ip = packet.Extract<PacketDotNet.IPPacket>();
            var tcp = packet.Extract<PacketDotNet.TcpPacket>();

            Console.WriteLine("============IP Packet============");
            Console.WriteLine("Src: {0} / Dst: {1} / TTL: {2}", ip.SourceAddress, ip.DestinationAddress, ip.TimeToLive);
            Console.WriteLine("============TCP Packet============");
            Console.WriteLine("Src Port: {0} / Dst Port: {1}", tcp.SourcePort, tcp.DestinationPort);
            string signal = "";
            if (tcp.Acknowledgment && tcp.Synchronize)
                signal = "[ACK | SYN]";
            else if (tcp.Acknowledgment)
                signal = "[ACK]";
            else if (tcp.Synchronize)
                signal = "[SYN]";

            if (signal != "")
                Console.WriteLine(signal);
            Console.WriteLine("Flag: {0}", tcp.Flags.ToString());

            Console.WriteLine("============HTTP Packet============");
            byte[] buffByte = new byte[rawPacket.Data.Length - 54];
            Buffer.BlockCopy(rawPacket.Data, 54, buffByte, 0, rawPacket.Data.Length - 54);
            Console.WriteLine(System.Text.Encoding.UTF8.GetString(buffByte));
            Console.WriteLine("===================================\n");
        }
    }
}