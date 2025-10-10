systemctl stop ebpf_firewall
make clean
make test_mode
make install

cp -f /home/ebpf-firewall/ddos-firewall/ebpf_firewall/build/ebpf_firewall_cli /home/ebpf-firewall/ddos-firewall/setup/payload/l4/bin/
cp -f /home/ebpf-firewall/ddos-firewall/ebpf_firewall/build/ebpf_firewall_prom /home/ebpf-firewall/ddos-firewall/setup/payload/l4/bin/
cp -f /home/ebpf-firewall/ddos-firewall/ebpf_firewall/build/ebpf_firewall_userspace /home/ebpf-firewall/ddos-firewall/setup/payload/l4/bin/
cp -f /home/ebpf-firewall/ddos-firewall/ebpf_firewall/build/firewall.config /home/ebpf-firewall/ddos-firewall/setup/payload/l4/
cp -f /home/ebpf-firewall/ddos-firewall/ebpf_firewall/build/ebpf_firewall_kernel.o /home/ebpf-firewall/ddos-firewall/setup/payload/l4/
cp -af /home/ebpf-firewall/ddos-firewall/ebpf_firewall/geodb/* /home/ebpf-firewall/ddos-firewall/setup/payload/l4/geodb/

cp -f /home/ebpf-firewall/ddos-firewall/api_parser/app.py /home/ebpf-firewall/ddos-firewall/setup/payload/api_parser/
cp -f /home/ebpf-firewall/ddos-firewall/api_parser/l7_nginx_config.py /home/ebpf-firewall/ddos-firewall/setup/payload/api_parser/
cp -f /home/ebpf-firewall/ddos-firewall/api_parser/api_parser.service /home/ebpf-firewall/ddos-firewall/setup/payload/api_parser/
