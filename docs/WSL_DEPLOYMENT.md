# Linux Subsystem and WSL Deployment

## WSL setup

```bash
wsl --install -d Ubuntu
sudo apt update
sudo apt install -y build-essential cmake libssl-dev
```

## Build and test

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Local relay validation in WSL

```bash
./build/syncstream_mobile_bridge
./build/syncstream_cli gen
```

## Integration notes

- Keep relay service inside WSL2 and expose only TLS ingress port to Windows host
- Use `.wslconfig` to reserve enough memory and CPU for relay plus media pipeline
- If using Docker Desktop with WSL backend, pin container limits and mount secrets read-only
