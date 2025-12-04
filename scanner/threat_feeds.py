
import requests
EPSS="https://api.first.org/data/v1/epss"
def query_epss(cve):
    try:
        r=requests.get(EPSS,params={"cve":cve},timeout=10)
        d=r.json()
        return d.get("data") or d.get("result")
    except: return None
