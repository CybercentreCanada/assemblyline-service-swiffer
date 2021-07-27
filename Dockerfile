ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

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

# Install dependencies for local pyswf library
RUN pip install --no-cache-dir --user lxml>=3.3.0 Pillow>=2.3.0 pylzma>=0.4.6 six && rm -rf ~/.cache/pip

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

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline

