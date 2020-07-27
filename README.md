# Name
encap_vxlan --- encapsulate vxlan in pcap file

# Synopsis
```
  encap_vxlan [infile [outfile [sa [da [sp [dp]]]]]]
```

# Description
default value:
* infile: in.pcap
* outfile: out.pcap
* sa: 0.0.0.0 (generate from packets in in.pcap)
* da: 0.0.0.0 (generate from packets in in.pcap)
* sp: 0 (generate from packets in in.pcap)
* dp: 4789 (default VxLAN port number)

[TBD]
