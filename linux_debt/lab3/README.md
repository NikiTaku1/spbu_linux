# Audit

## Preset

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

Start logging

```bash
./audit --pid $PID > logs
```

Read target system code logs

```bash
cat logs | grep "system_code=$SYSTEM_CODE"
```
