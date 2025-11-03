# !/bin/bash

### build docker image
### docker build -f Dockerfile -t cs305py312 .

### continue
### docker exec -it contain_name bash

### run docker image
docker run -it \
  --gpus all \
  -v $HOME/project/ta/cs305-proj:/cs305-proj \
  --name testp2p \
  cs305py312 \
  bash
