# Agent image of a swarmlabre run (`swarmlabre-agent`): the pi coding agent and basic tools. Build: docker build -t swarmlabre-agent sandbox/
# Deliberately small: pi, basic tools and helpers from apt (no pip at build or run time). No extensions, no web tools, no keys, no host config. The container has no network.
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ripgrep fd-find curl ca-certificates python3 \
    poppler-utils pandoc jq libxml2-utils sqlite3 python3-pandas python3-matplotlib \
    weasyprint fonts-dejavu-core fonts-liberation \
    && ln -s "$(command -v fdfind)" /usr/local/bin/fd \
    && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null; rm -rf /var/lib/apt/lists/*
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent@1.1.0
# the container has no network: this forwarder and entry script give pi a loopback URL for the run's model socket
COPY sock-fwd.js /usr/local/lib/sock-fwd.js
COPY --chmod=755 swarmlabre-net-entry /usr/local/bin/swarmlabre-net-entry
ENV HOME=/home/agent MPLBACKEND=Agg
RUN mkdir -p /work /home/agent && chmod 1777 /work /home/agent
WORKDIR /work
