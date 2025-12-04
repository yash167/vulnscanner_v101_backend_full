
import subprocess, xml.etree.ElementTree as ET

def run_nmap_scan(target, ports):
    cmd=["nmap","-p",ports,"-sV","-oX","-",target]
    try:
        xml=subprocess.check_output(cmd).decode()
        return parse(xml)
    except Exception as e:
        return {"error":str(e)}

def parse(x):
    try: root=ET.fromstring(x)
    except: return {"error":"bad xml"}
    out=[]
    for host in root.findall("host"):
        for p in host.findall("ports/port"):
            if p.find("state").attrib.get("state")!="open": continue
            s=p.find("service")
            name=s.attrib.get("name","unknown") if s is not None else "unknown"
            prod=s.attrib.get("product","") if s is not None else ""
            ver=s.attrib.get("version","") if s is not None else ""
            full=(prod+" "+ver).strip()
            out.append({"port":int(p.attrib["portid"]),"service":name,"version":full})
    return out
