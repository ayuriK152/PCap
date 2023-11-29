using System;
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

            string filter = "tcp src port 80";
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
            /*var dhcp = packet.Extract<PacketDotNet.Http>();*/
            var ip = packet.Extract<PacketDotNet.IPPacket>();
            var tcp = packet.Extract<PacketDotNet.TcpPacket>();

            Console.WriteLine("");
            Console.WriteLine(packet);
            /*Console.WriteLine("============IP Packet============");
            Console.WriteLine("Src: {0} / Dst: {1} / TTL: {2}", ip.SourceAddress, ip.DestinationAddress, ip.TimeToLive);
            Console.WriteLine("============TCP Packet============");
            Console.WriteLine("Src Port: {0} / Dst Port: {1}", tcp.SourcePort, tcp.DestinationPort);
            Console.WriteLine("============DHCP Packet============");
            Console.WriteLine("Your IP address: " + dhcp.YourAddress);
            Console.WriteLine("Your MAC address: " + dhcp.ClientHardwareAddress);
            Console.WriteLine("DHCP MessageType: " + dhcp.MessageType);
            if (dhcp.MessageType.ToString() == "Request")
            {
                Console.WriteLine("Client ID: " + dhcp.GetOptions()[1]);
                Console.WriteLine("Requested IP address: " + dhcp.GetOptions()[2]);
                Console.WriteLine("HostName: " + dhcp.GetOptions()[3]);
            }
            if (dhcp.MessageType.ToString() == "Ack")
            {
                Console.WriteLine("Server ID: " + dhcp.GetOptions()[1]);
                Console.WriteLine("SubnetMask: " + dhcp.GetOptions()[3]);
                Console.WriteLine("Router: " + dhcp.GetOptions()[4]);
            }*/
            Console.WriteLine("===================================");
        }
    }
}