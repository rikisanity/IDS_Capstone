# STEP 1: Use the Official Zeek Image
FROM zeek/zeek:lts

# STEP 2: Install tools (Added 'mosquitto-clients' for IoT simulation)
RUN apt-get update && apt-get install -y \
    netsniff-ng \
    iproute2 \
    python3 \
    python3-pip \
    nano \
    wget \
    mosquitto-clients \
    && rm -rf /var/lib/apt/lists/*

# STEP 3: Install Pandas
RUN pip3 install pandas --break-system-packages

# STEP 4: Setup workspace
WORKDIR /app
RUN mkdir -p /app/captures

# STEP 5: Add Zeek to path
ENV PATH=$PATH:/usr/local/zeek/bin

# Keep container running
CMD ["tail", "-f", "/dev/null"]

