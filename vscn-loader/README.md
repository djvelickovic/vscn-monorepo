# VSCN Server

## Running

```bash
python3 -m venv venv
. venv/bin/activate

pip install pymongo
pip install dnspython
pip install requests
pip install python-dotenv

```

create .env file in the root of the project and add:

```env
MONGO_DB_URL=<url goes here>
```
