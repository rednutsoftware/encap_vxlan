project( encap_vxlan C )

add_executable( encap_vxlan
	encap_vxlan.c )

target_link_libraries( encap_vxlan
	pcap )
