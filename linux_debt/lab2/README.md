# Network scanner

Collects information about ip addresses

## Preset

```bash
pip install tkinter
pip install scapy
pip install requests
```

## Usage

If you don't run with sudo, scapy may not work

```bash
sudo python main.py
```

You can enter target ips/ports in foramt `item,item,item1-itemN,item` where item - one element, item1-itemN - range
If ports not specified it is equal to 1-1024

You can filter result by country

You can save result in specified file
