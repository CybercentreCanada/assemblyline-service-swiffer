FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH swiffer.swiffer.Swiffer

USER root

# Install APT dependancies
RUN apt-get update && apt-get install -y \
  libjpeg-dev \
  snapd \
  && rm -rf /var/lib/apt/lists/*

RUN pip install Pillow==2.3.0 && rm -rf ~/.cache/pip

######################################################
# Execute a builder step
FROM base AS builder

# Install build dependancies
RUN apt-get update && apt-get install -y \
  unzip \
  && rm -rf /var/lib/apt/lists/*

# Install rabcdasm
RUN snap install dmd --classic
RUN curl -L https://github.com/CyberShadow/RABCDAsm/archive/7818a79009fdee03f9df70bf2dfe534c6767dc60.zip -o /tmp/rabcdasm.zip
RUN mkdir -p /opt/al_support/swiffer
RUN unzip /tmp/rabcdasm.zip -d /tmp
RUN mv /tmp/RABCDAsm-7818a79009fdee03f9df70bf2dfe534c6767dc60 /opt/al_support/swiffer/rabcdasm
# TODO compile rabcdasm with DMD ... I can't make it work for some reason...

# Install pyswf
RUN aws s3 cp s3://assemblyline-support/pyswf-master-custom-patched.tgz /tmp
USER assemblyline
RUN touch /tmp/before-pip
RUN pip install --user /tmp/pyswf-master-custom-patched.tgz && rm -rf ~/.cache/pip
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

#####################################################
# Restart from base
FROM base

# Copy output directories from the builder step
COPY --from=builder /opt/al_support /opt/al_support
COPY --chown=assemblyline:assemblyline --from=builder /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Get Swiffer service code
WORKDIR /opt/al_service
COPY . .

# Switch to assemblyline user
USER assemblyline

