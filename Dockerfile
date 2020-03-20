FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH swiffer.swiffer.Swiffer

USER root

# Install APT dependancies
RUN apt-get update && apt-get install -y \
  libjpeg-dev \
  && rm -rf /var/lib/apt/lists/*

######################################################
# Execute a builder step
FROM base AS builder

# Install builder dependancies
RUN apt-get update && apt-get install -y \
  build-essential \
  && rm -rf /var/lib/apt/lists/*

# Set a marker to copy pip files
RUN touch /tmp/before-pip

# Install dependancies as Assemblyline
USER assemblyline

# Install pyswf
RUN pip install --user https://github.com/timknip/pyswf/archive/master.zip && rm -rf ~/.cache/pip

# Downgrade Pillow for compatibility reasons
RUN pip install --user Pillow==2.3.0 && rm -rf ~/.cache/pip

# Delete files that are not to be kept
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Set owner to be root for COPY from builder to work properly
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

#####################################################
# Restart from base
FROM base

# Copy pip packages from the builder step
COPY --chown=assemblyline:assemblyline --from=builder /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Copy service and dependancy code from source
COPY ./remnux-rabcdasm/* /opt/al_support/swiffer/rabcdasm/
COPY ./swiffer /opt/al_service/swiffer
COPY service_manifest.yml /opt/al_service

# Switch to assemblyline user
WORKDIR /opt/al_service
USER assemblyline

