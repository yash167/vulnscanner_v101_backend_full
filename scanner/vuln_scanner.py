
import os, json, requests
from .threat_feeds import query_epss

NVD="https://services.nvd.nist.gov/rest/json/cves/2.0"
DB=os.path.join(os.path.dirname(__file__), "..","custom_cve_db.json")

def load_db():
    try: return json.load(open(DB))
    except: return {"signatures":[]}

def nvd_query(kw,key):
    try:
        r=requests.get(NVD,params={"keywordSearch":kw,"resultsPerPage":20},headers={"apiKey":key})
        return r.json()
    except Exception as e:
        return {"error":str(e)}

def correlate(name,ver,key):
    db=load_db()
    res={"service":name,"version":ver,"matched_cves":[],"custom_matches":[],"epss":{}}

    target=f"{name} {ver}".lower()
    for sig in db["signatures"]:
        if sig["match"] in target:
            res["custom_matches"].append(sig)

    nvd=nvd_query(target,key)
    res["nvd_raw"]=nvd

    cves=[]
    for v in nvd.get("vulnerabilities",[])[:20]:
        cid=v.get("cve",{}).get("id")
        if cid: cves.append(cid)
    res["matched_cves"]=cves

    ae=False
    scored=[]
    for c in cves:
        epss=query_epss(c)
        score=None
        if epss and isinstance(epss,list):
            try: score=float(epss[0].get("epss",0))
            except: score=None
        if score and score>0.5: ae=True
        scored.append({"cve":c,"epss":score,"cvss":5.0,"score":5.0*(1+(score or 0))})
        res["epss"][c]=epss
    res["risk_scored"]=scored
    res["actively_exploited"]=ae
    return res
