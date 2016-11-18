# mruby-bpf
"mruby-bpf" provides BPF (Berkeley Packet Filter) API to mruby.

## Example
```rb
bpf = BPF.open("em1", 2000)
bpf.immediate = true

while IO.select([bpf])
  pkt = bpf.sysread(bpf.buffer_length)
  p pkt
end
bpf.close
```

## API

- BPF.open(ifname, buflen=nil)
  - Open a BPF device file.  `ifname` is the name of the hardware interface that the BPF object will listen on.  `buflen` is the buffer length for reads.  The default value of `buflen` varies per systems.
- BPF#buffer_length
  - Returns the required buffer length (BIOCGBLEN)
- BPF#buffer_length=
  - Sets the buffer length for reads (BIOCSBLEN)
- BPF#header_complete
  - Get the status of the "header complete" flag (BIOCGHDRCMPLT)
- BPF#header_complete=
  - Set the status of the "header complete" flag (BIOCSHDRCMPLT)
- BPF#immediate=
  - Enables or disables "immediate mode" (BIOCIMMEDIATE).
    Note: BPF does not provide an API to get the status of "immediate mode".
- BPF#interface
  - Returns the name of the hardware interface that the BPF object is
    listening on (BIOCGETIF)
- BPF#interface=
  - Sets the hardware interface (BIOCSETIF)
- BPF#see_sent
  - Get the status of the "see sent" flag (BIOCGSEESENT)
- BPF#see_sent=
  - Set the status of the "see sent" flag (BIOCSSEESENT)
- BPF#set_filter(prog)
  - Sets the filter program used by the kernel to discard uninteresting packets
    (BIOCSETF).  `prog` is expected to be an output of `tcpdump -ddd`.
- BPF#set_promisc
  - Forces the interface into promiscuous mode (BIOCPROMISC)
- BPF.wordalign(x)
  - Returns `BPF_WORDALIGN(x)` (see bpf(4)).


## License

Copyright (c) 2015 Internet Initiative Japan Inc.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
