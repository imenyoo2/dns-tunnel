


run tunnel: tunnel
	./target/debug/tunnel


tunnel:
	gcc src/tunnel.c -o target/debug/tunnel
