package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf bpf_prog.c

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lookup network iface %q: %s", ifaceName, err)
	}

	bpfObj := bpfObjects{}
	if err := loadBpfObjects(&bpfObj, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer bpfObj.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   bpfObj.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not attach XDP program: %s", err)
	}
	defer l.Close()

	fmt.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	fmt.Println("Press Ctrl-C to exit and remove the program")

	// Open a ringbuf reader from userspace RINGBUF map described in the eBPF C program.
	rd, err := ringbuf.NewReader(bpfObj.Events)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	defer rd.Close()

	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// received a signal, exiting
					return
				}
				fmt.Println(err)
				continue
			}
			e, err := parseEvent(rec.RawSample)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Printf("%s -> %s\n", e.source(), e.destination())
		}
	}()
	<-ctx.Done()
}

type bpfEvent struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type event struct {
	Saddr netip.Addr
	Sport uint16
	Daddr netip.Addr
	Dport uint16
}

func (e *event) source() string {
	return fmt.Sprintf("%s:%d", e.Saddr, e.Sport)
}

func (e *event) destination() string {
	return fmt.Sprintf("%s:%d", e.Daddr, e.Dport)
}

func parseEvent(inBytes []byte) (event, error) {
	var bpfEvent bpfEvent
	if err := binary.Read(bytes.NewBuffer(inBytes), binary.LittleEndian, &bpfEvent); err != nil {
		return event{}, fmt.Errorf("parsing ringbuf event: %s", err)
	}
	return event{
		Saddr: uint32ToIPv4(bpfEvent.Saddr),
		Daddr: uint32ToIPv4(bpfEvent.Daddr),
		Sport: bpfEvent.Sport,
		Dport: bpfEvent.Dport,
	}, nil
}

func uint32ToIPv4(ip uint32) netip.Addr {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, ip)
	ipv4, _ := netip.AddrFromSlice(bs)
	return ipv4
}
