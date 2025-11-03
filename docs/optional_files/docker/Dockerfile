# Ubuntu 22.04
FROM ubuntu:22.04

ENV PYTHON_VERSION=3.10

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# update and install necessary packages
RUN apt-get update && apt-get install -y \
    software-properties-common \
    wget \
    curl \
    git \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

# install python3.10 (in default for ubuntu:22.04)
RUN apt-get update && apt-get install -y python3 python3-pip


# python libs
RUN pip install \
    pytest \
    matplotlib \
    numpy \
    pandas

# workdir
WORKDIR /workspace


CMD ["/bin/bash"]
