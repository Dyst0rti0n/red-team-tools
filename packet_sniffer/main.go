package main

import (
    "encoding/csv"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/manifoldco/promptui"
)

func main() {
    interfaces, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatalf("Error finding devices: %v\n", err)
    }

    if len(interfaces) == 0 {
        log.Fatalf("No network interfaces found.")
    }

    iface, err := selectInterface(interfaces)
    if err != nil {
        log.Fatalf("Error selecting interface: %v\n", err)
    }

    handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("Error opening adapter: %v\n", err)
    }
    defer handle.Close()

    file, err := os.Create("packets.csv")
    if err != nil {
        log.Fatalf("Error creating CSV file: %v\n", err)
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Write CSV header
    writer.Write([]string{"Timestamp", "Source", "Destination", "Transport Layer", "Source Port", "Destination Port", "Payload", "Error"})

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        err := logPacketInfo(writer, packet)
        if err != nil {
            fmt.Printf("Error logging packet: %v\n", err)
        }
    }
}

func selectInterface(interfaces []pcap.Interface) (*pcap.Interface, error) {
    items := make([]string, len(interfaces))
    for i, iface := range interfaces {
        items[i] = fmt.Sprintf("%s - %s", iface.Name, iface.Description)
    }

    prompt := promptui.Select{
        Label: "Select Network Interface",
        Items: items,
    }

    index, _, err := prompt.Run()
    if err != nil {
        return nil, err
    }

    return &interfaces[index], nil
}

func logPacketInfo(writer *csv.Writer, packet gopacket.Packet) error {
    timestamp := time.Now().Format(time.RFC3339)
    var src, dst, transportType, srcPort, dstPort, payload, errorLayer string

    networkLayer := packet.NetworkLayer()
    if networkLayer != nil {
        src = networkLayer.NetworkFlow().Src().String()
        dst = networkLayer.NetworkFlow().Dst().String()
    }

    transportLayer := packet.TransportLayer()
    if transportLayer != nil {
        transportType = transportLayer.LayerType().String()
        srcPort = transportLayer.TransportFlow().Src().String()
        dstPort = transportLayer.TransportFlow().Dst().String()
    }

    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        payload = string(applicationLayer.Payload())
    }

    if packet.ErrorLayer() != nil {
        errorLayer = packet.ErrorLayer().Error().Error()
    }

    record := []string{timestamp, src, dst, transportType, srcPort, dstPort, payload, errorLayer}
    err := writer.Write(record)
    writer.Flush()
    return err
}
