

## Build

```
earthly --platform=linux/amd64 +build

docker push gcr.io/leafy-beach-375514/vscn-loader:1.0.0_linux_amd64

docker push gcr.io/leafy-beach-375514/vscn-server:1.0.0_linux_amd64
```

## Run

```
docker-compose up
```