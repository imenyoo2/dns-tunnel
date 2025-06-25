

push:
	cp ./target/debug/server ~/goinfre
	cp ./target/debug/client ~/goinfre
	cp ./target/debug/tunnel ~/goinfre

ip:
	sudo ip addr add 10.0.0.1/24 dev tun38
	sudo ip link set dev tun38 up

run tunnel: tunnel
	./target/debug/tunnel


tunnel:
	gcc src/tunnel.c -o target/debug/tunnel
