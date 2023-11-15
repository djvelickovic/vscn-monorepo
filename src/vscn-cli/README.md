# VSCN Server

## Setup

```bash
python3 -m venv venv

. venv/bin/activate

pip install -r requirements.txt

```


## Develop

```bash
python setup.py develop

vscnc scan -t mvn -d enigma-engine

pip uninstall vscn
```

## Release

```bash
pip install wheel
python setup.py bdist_wheel
pip install dist/vscnc-1.0.0-py3-none-any.whl
```


# Run

```bash
vscnc scan -t mvn -d {root_dir_path}
vscnc scan -t pip -d {venv_dir_path}

# override url
vscnc scan -u http://localhost:3000 -t mvn -d {root_dir_path}
```