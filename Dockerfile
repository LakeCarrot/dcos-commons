FROM ubuntu:latest
RUN apt-get update && apt-get install -y \
    python3 \
    git \
    curl \
    golang \
    jq \
    default-jdk \
    python-pip \
    python3-dev \
    python3-pip \
    libssl-dev \
    wget \
    zip
RUN pip install awscli
RUN pip3 install dcoscli dcos-shakedown
RUN wget https://downloads.dcos.io/dcos-test-utils/bin/linux/dcos-launch -O /usr/bin/dcos-launch
RUN chmod +x /usr/bin/dcos-launch
# shakedown and dcos-cli require this
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
