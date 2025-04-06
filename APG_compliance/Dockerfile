# Base image
FROM python:3.9-slim

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive
ENV STORAGE_DRIVER=overlay
ENV XDG_RUNTIME_DIR=/tmp
ENV DOCKER_HOST=unix:///tmp/podman/podman.sock

RUN apt-get update && apt-get install -y \
    curl \
    sudo \
    lsb-release \
    ca-certificates \
    && curl -fsSL https://get.docker.com -o get-docker.sh \
    && sh get-docker.sh \
    && rm -f get-docker.sh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the Docker Hub username and token as build arguments

# Install dependencies, Trivy, and Podman
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    uidmap \
    fuse-overlayfs \
    slirp4netns \
    iptables \
    podman \
    python3-pip \
    && wget https://github.com/aquasecurity/trivy/releases/download/v0.24.0/trivy_0.24.0_Linux-64bit.tar.gz \
    && tar zxvf trivy_0.24.0_Linux-64bit.tar.gz \
    && mv trivy /usr/local/bin/ \
    && rm trivy_0.24.0_Linux-64bit.tar.gz \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Verify installations
RUN python --version && pip --version && podman --version

# Create directory for Podman socket
RUN mkdir -p /tmp/podman

# Set working directory
WORKDIR /app

# Copy Python dependencies and install them
COPY requirements.txt requirements.txt
RUN python3 -m pip install --no-cache-dir -r requirements.txt
RUN pip install kubernetes
RUN pip install ilcli
# Copy application code
COPY . .

#CMD podman system service unix:///tmp/podman/podman.sock --time=0 & python main.py

CMD ["python3", "main.py" ]

# Run Podman service in the background and then start the Python app
#CMD podman system service unix:///tmp/podman/podman.sock --time=0
