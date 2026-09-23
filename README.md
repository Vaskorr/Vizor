# Vizor

Vizor is a self-hosted internal network monitoring service powered by Nmap. It schedules scans, stores scan history in SQLite, compares snapshots, searches hosts, ports, services, banners and NSE output, imports Nmap XML files, and exports change reports to PDF.

## Requirements

- Docker Engine with Docker Compose
- Network access from the Docker host to the authorized target subnets

## Installation

```bash
git clone https://github.com/Vaskorr/Vizor.git
cd Vizor
docker compose up --build -d
```

Open:

- Web interface: <http://localhost:3000>
- API documentation: <http://localhost:8000/docs>

On first launch, open **Settings**, add the network segments you are authorized to scan, review the Nmap flags and NSE scripts, configure the schedule, and save the configuration.

Application data is stored in the `vizor-data` Docker volume. The container is granted `NET_RAW` and `NET_ADMIN` capabilities for Nmap and exposes both services on localhost only.

## Operations

```bash
# View status and logs
docker compose ps
docker compose logs -f

# Stop Vizor
docker compose down

# Update and restart
git pull
docker compose up --build -d
```

## Security

Vizor never invokes Nmap through a shell. Additional Nmap arguments are parsed into an argument array and validated against the Nmap 7.x scan-option grammar, including options with separate, attached, or `--option=value` parameters. Unknown options and positional arguments are rejected. Vizor exclusively manages scan targets and output files; input-file, data-directory, resume, arbitrary output, and NSE script-path options are blocked. Scan targets and exclusions must be IP addresses or CIDR networks, and NSE selectors accept only installed script/category names or selector expressions.

Use Vizor only on networks for which you have explicit authorization.
