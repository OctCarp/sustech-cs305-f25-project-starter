## Using Docker (Optional)

### Note

If you want to use Docker, you can refer to these files and move them to the root directory of your project.

### Files

- `Dockerfile` : Docker build script using `ubuntu:22.04` image
- `Dockerfile_alt` : Alternative Docker build script using `python:3.12` image, with copy local file to image.
- `.dockerignore` :  Docker ignore files
- `run_docker` : Run script for reference

## Commands

### Build Image

```bash
docker build -f <build file> -t <image name> .
```

for example

```bash
docker build -f Dockerfile -t cs305py312 .
```

### Run container

```bash
docker run -it \
  --gpus all \
  -v $HOME/cs305-proj:/cs305-proj \
  --name testp2p \
  cs305py312 \
  bash
```

- `docker run`: Create & start a container.
- `-it`: Interactive shell for input/terminal.
- `--gpus all`: Enable GPU access.
- `-v $HOME/cs305-proj:/cs305-proj`: Mount project folder (Sync code.)
- `--name testp2p`: Name the container as "testp2p".
- `cs305py312`: Base Image.
- `bash`: Run Bash shell (keep container alive).
