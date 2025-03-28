from flask import Flask, jsonify, Response, request, abort

app = Flask(__name__)

@app.route('/api/ec/dev/app/emjoin', methods=['POST'])
def emjoin():
    data = {"msg": "ok", "errcode": "0", "code": 0, "msgShowType": "none",
            "workbench_url_pc": "/spa/portal/static4em/index.html#/main",
            "rsa_pub": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgRvErN4B1eBBEeJsFPOghggMFij5JYBgiIGSrgu9Sk0SJyrnxc2MUDXb6gNiS6KgAWeIHt3JHa8Ihy5GuSxfr/QFoG76yVp1DvAWQFNxJiLkbsOI3i5m2Yl/oJ5lROljPNjGUTDaKQ18+dIxrKCg+IFciAHZKFjvbkXVbj20CdWJ7igxJyNdlMHB0ELqgB3+QG/Qy96nZbaWvC3xvH3gmFXUlp3ztzvY8Ep++k1DgTpQyPVho7eKLCaA+k2wQWUv62Qd6dgMdF0FHAKc63kCLdds9bE7AcCIgLxlbbuKRaMDuMqprW4KGDjeq2vdwe+gRDi8YRa6+PduZWSCAiX/wwIDAQAB",
            "errmsg": "ok",
            "workbench_url": "/spa/coms/static4mobile/index.html#/menu-preview?id=appDefaultPage&checkAccess=1",
            "status": True}
    return jsonify(data)


@app.route('/weaver/weaver.file.FileDownloadForEM', methods=['POST'])
def file():
    fileid = request.json.get("fileid")
    print(fileid)
    if int(fileid) > 500000000:
        return abort(404)
    elif int(fileid) > 100000000 and int(fileid) < 500000000:
        response = Response(open("404.html", encoding="utf-8").read())
        response.headers['hasRight'] = '1'
        response.headers['Content-Disposition'] = 'attachment; filename=../page/client/common/error.html'
        return response


@app.route('/api/ec/dev/app/checkSSOCode', methods=['POST'])
def checkSSOCode():
    data = {"msg": "ok", "errcode": "0", "UserId": "1"}
    return jsonify(data)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=88)