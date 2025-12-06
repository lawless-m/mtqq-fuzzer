# Docker-based MQTT Fuzzing

Portable fuzzing setup that runs anywhere Docker is installed.

## Quick Start

### Local Testing

```bash
cd docker
./run_docker_fuzzing.sh
```

### Remote Server Deployment

**Copy project to server:**
```bash
# From your local machine
rsync -av --exclude 'logs' --exclude 'boofuzz-results' \
  /home/matt/Git/mtqq-fuzzer/ user@remote-server:~/mtqq-fuzzer/
```

**On remote server:**
```bash
cd ~/mtqq-fuzzer/docker
./run_docker_fuzzing.sh
```

Or run in background:
```bash
tmux new -s fuzzing
./run_docker_fuzzing.sh
# Detach: Ctrl+B, D
```

## What Gets Tested

- **Target**: EMQX v5.8.3 with AddressSanitizer (C NIFs)
- **Test Cases**: 171,554+ malformed MQTT packets
- **Duration**: ~5-6 hours
- **Container isolation**: Fuzzer and target in separate containers
- **Build time**: ~10-15 minutes (EMQX is large)

## Architecture

```
┌─────────────────┐     MQTT 1883      ┌─────────────────┐
│  mqtt-fuzzer    │ ─────────────────> │  emqx-target    │
│  (Python)       │                     │  (Erlang + C)   │
└─────────────────┘                     │  (ASAN NIFs)    │
        │                               └─────────────────┘
        │                                        │
        └──── results/ ────────────────── logs/ ─┘
```

## Monitoring

**Watch fuzzer output:**
```bash
docker compose logs -f fuzzer
```

**Watch EMQX logs:**
```bash
docker compose logs -f emqx
```

**Check container status:**
```bash
docker compose ps
```

## Results

After completion:
- **ASAN logs**: `logs/asan.*`
- **Fuzzing database**: `results/*.db`
- **Campaign log**: `logs/campaign-TIMESTAMP.log`

**Check for crashes:**
```bash
grep -i 'error\|asan\|heap\|buffer' logs/asan.*
```

**Analyze database:**
```bash
sqlite3 results/*.db
SELECT COUNT(*) FROM cases;
```

## Manual Control

**Start services separately:**
```bash
docker compose up -d emqx      # Start EMQX
docker compose up fuzzer       # Run fuzzer (foreground)
```

**Stop everything:**
```bash
docker compose down
```

**Rebuild after changes:**
```bash
docker compose build --no-cache
```

## Resource Requirements

- **Memory**: 4GB minimum (ASAN overhead)
- **Disk**: ~500MB for images, ~500MB for results
- **Network**: Bridge network (no external access needed)

## Troubleshooting

**EMQX won't start:**
```bash
docker compose logs emqx
docker compose exec emqx pgrep beam.smp
```

**Fuzzer can't connect:**
```bash
docker compose exec fuzzer nc -zv emqx 1883
```

**Out of memory:**
```bash
# Increase mem_limit in docker-compose.yml
mem_limit: 8g
```

## Files

- `Dockerfile.emqx` - ASAN-instrumented EMQX (C NIFs)
- `Dockerfile.fuzzer` - Python fuzzer with boofuzz
- `docker-compose.yml` - Multi-container orchestration
- `run_docker_fuzzing.sh` - Complete campaign runner
- `logs/` - ASAN and campaign logs
- `results/` - Fuzzing databases

## Notes

- EMQX is written in Erlang with C NIFs (Native Implemented Functions)
- ASAN instruments the C code only, not Erlang VM
- Build takes longer (~10-15 min) due to Erlang compilation
- EMQX v5.8.3 is the latest stable version

## Deployment Tips

**For long-running campaigns on remote servers:**

1. Use tmux/screen to detach
2. Monitor with `docker compose logs -f`
3. Save logs before stopping: `docker compose logs > full-campaign.log`
4. Copy results back: `rsync -av user@server:~/mtqq-fuzzer/docker/results/ ./`

**For multiple parallel campaigns:**
```bash
# Copy to different directories
cp -r docker campaign1
cp -r docker campaign2

cd campaign1 && ./run_docker_fuzzing.sh &
cd campaign2 && ./run_docker_fuzzing.sh &
```
