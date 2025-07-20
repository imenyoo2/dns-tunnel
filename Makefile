

push:
	cp ./target/debug/server ~/linux_share
	cp ./target/debug/client ~/linux_share
	cp ./target/debug/tunnel ~/linux_share

#push:
#	cp ./target/debug/server ~/goinfre/
#	cp ./target/debug/client ~/goinfre/
#	cp ./target/debug/tunnel ~/goinfre/

server ip:
	sudo ip addr add 10.0.0.1/24 dev tun39
	sudo ip link set dev tun39 up
	sudo ip link set dev tun39 mtu 110

ip:
	sudo ip addr add 10.0.0.2/24 dev tun38
	sudo ip link set dev tun38 up
	sudo ip link set dev tun38 mtu 110

run tunnel: tunnel
	./target/debug/tunnel


tunnel:
	gcc src/tunnel.c -o target/debug/tunnel
