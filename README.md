<div align="center">

# Search & Destroy 🕵️
## Threat detection through rules in ELK stack to detect APTs

<img src="https://img.shields.io/badge/License_-GPL%203.0-orange"> 
<img src="https://img.shields.io/badge/python_->=%203.1-blue"> 
<img src="https://img.shields.io/badge/Version-v0.4.7-yellow">

### [Video Demo](https://www.youtube.com/watch?v=o6MVD5Ld9hk) | [Source Code](https://github.com/4n33sh/SearchAndDestroy/blob/main/main.py)

</div>

---

<img width="2991" height="1970" alt="elk-export" src="https://github.com/user-attachments/assets/02e5d28f-343a-4ff2-8902-78ddfb57dcff" />

---

# Installation & Running

* (optional) **Create & activate** new python **virtual (.venv) environment** and update pip configs :  ``` python3 -m venv ~/your/preffered/path && source ~/your/preffered/path/bin/activate && pip install --upgrade pip setuptools wheel ```

* (optional) (only if setup.py/requirements.txt fails) Install required **external packages/modules** (~250-300mb) : ``` pip install black mypy flask kafka-python elasticsearch logstash requests ```

* **Clone** the repo into your preferred directory : ``` git clone https://github.com/4n33sh/SearchAndDestroy.git ```

* Change directory **(cd)** into OceanQuery and install the requirements : ``` cd SearchAndDestroy && pip install -r requirements.txt ```

* Setup an docker container (if not already setup) and run in background : ``` sudo apt install docker docker-compose -y ; docker-compose up -d ```

* Alter **permissions** of **main.py** file and **run** it : ``` chmod u+x main.py && python3 main.py ```

---
