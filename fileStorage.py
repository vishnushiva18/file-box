import os
from telethon import TelegramClient, events, sync, types
from flask import (Flask,session, g, json, Blueprint,flash, jsonify, redirect, render_template, request,
                   url_for, send_from_directory, send_file, make_response)
from werkzeug.utils import secure_filename
from asgiref.sync import async_to_sync, sync_to_async
import asyncio
import uuid 
import db.connections as conn
import db.db as db
import io
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

tgApp = None
api_id = 50689
api_hash = '2b7f12faf2e1f06d9403213185525af2'
uploadFromBlob = True
    

class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class tgClient:
    def __init__(self):
        return


    async def getMe(self, loop):
        async with TelegramClient('file_storage', api_id, api_hash, loop = loop) as client:
            _r = await client.get_me()
            return _r
        
    async def downloadFile(self, loop, chat, messageId, filePath):
        # try
        if 1==1:
            async with TelegramClient('file_storage', api_id, api_hash, loop = loop) as client:
                _message = await client.get_messages(chat, ids=messageId)
                _bdata = await _message.download_media(file=bytes)
                return _bdata
        
    async def downloadFile1(self, loop, chat, messageId, filePath):
        # try
        if 1==1:
            async with TelegramClient('file_storage', api_id, api_hash, loop = loop) as client:
                _message = await client.get_messages(chat, ids=messageId)
                await client.download_media(_message, filePath, progress_callback=callback)

        return True

    async def uploadBlob(self, loop, file_blob, _caption = None):
        # try:
        if 1==1:
            async with TelegramClient('file_storage', api_id, api_hash, loop = loop) as client:
                _r = await client.send_file('me', file = file_blob, caption = _caption)
                    
                _data = {
                    'message_id' : _r.id,
                    'account' : _r.peer_id.user_id,
                    'file_name' : None
                }

                _media = {
                    'type' : _r.media.to_dict()['_']
                }

                print(_r.stringify())
                if _r.media.to_dict()['_'] == 'MessageMediaPhoto':
                    _data['file_id'] = _r.media.photo.id
                    _data['access_hash'] = _r.media.photo.access_hash
                    _data['size'] = 0
                    # _data['file_reference'] = _r.media.photo.file_reference
                    for _size in _r.media.photo.sizes:
                        if _size.to_dict()['_'] == 'PhotoSize':
                            _data['size'] = _size.size

                    _media['w'] = _r.media.photo.sizes[1].w
                    _media['h'] = _r.media.photo.sizes[1].h

                elif _r.media.to_dict()['_'] == 'MessageMediaDocument':
                    _file_name = None

                    for _da in _r.media.document.attributes:
                        _da_type = _da.to_dict()['_']
                        if _da_type == "DocumentAttributeFilename":
                            _file_name = _da.file_name

                        if _da_type == "DocumentAttributeVideo":
                            _media['supports_streaming'] = _da.supports_streaming
                            _media['duration'] = _da.duration

                    _data['file_id'] = _r.media.document.id
                    _data['access_hash'] = _r.media.document.access_hash
                    _data['file_name'] = _file_name
                    _data['size'] = _r.media.document.size
                    _data['mime_type'] = _r.media.document.mime_type
                    # _data['file_reference'] = _r.media.document.file_reference
                    

                else:
                    print(_r.media.to_dict()['_'])

                _data['media'] = _media

                return _data
            
        # except:
        #     return False

    async def uploadFile(self, loop, filePath, _caption = None):
        # try:
        if 1==1:
            async with TelegramClient('file_storage', api_id, api_hash, loop = loop) as client:
                _r = await client.send_file('me', filePath, caption = _caption)
                    
                _data = {
                    'message_id' : _r.id,
                    'account' : _r.peer_id.user_id,
                    'file_name' : None
                }

                _media = {
                    'type' : _r.media.to_dict()['_']
                }

                print(_r.stringify())
                if _r.media.to_dict()['_'] == 'MessageMediaPhoto':
                    _data['file_id'] = _r.media.photo.id
                    _data['access_hash'] = _r.media.photo.access_hash
                    _data['size'] = 0
                    # _data['file_reference'] = _r.media.photo.file_reference
                    for _size in _r.media.photo.sizes:
                        if _size.to_dict()['_'] == 'PhotoSize':
                            _data['size'] = _size.size

                    _media['w'] = _r.media.photo.sizes[1].w
                    _media['h'] = _r.media.photo.sizes[1].h

                elif _r.media.to_dict()['_'] == 'MessageMediaDocument':
                    _file_name = None

                    for _da in _r.media.document.attributes:
                        _da_type = _da.to_dict()['_']
                        if _da_type == "DocumentAttributeFilename":
                            _file_name = _da.file_name

                        if _da_type == "DocumentAttributeVideo":
                            _media['supports_streaming'] = _da.supports_streaming
                            _media['duration'] = _da.duration

                    _data['file_id'] = _r.media.document.id
                    _data['access_hash'] = _r.media.document.access_hash
                    _data['file_name'] = _file_name
                    _data['size'] = _r.media.document.size
                    _data['mime_type'] = _r.media.document.mime_type
                    # _data['file_reference'] = _r.media.document.file_reference
                    

                else:
                    print(_r.media.to_dict()['_'])

                _data['media'] = _media

                return _data
            
        # except:
        #     return False


UPLOAD_FOLDER = 'tempFiles'

app = Flask(__name__)
app.config.from_object(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['SECRET_KEY'] = "vishnu-file-upload-dev-key"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'mp4', 'apk'}

# @async_to_sync
# async def getMe(_client):
#     print('in getMe')
#     # await _client.send_message('me', 'Hello to myself!')
#     _r = await _client.get_me()
#     return _r.stringify()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def writeFileBox(data):
    _uid = data['file_uid'].replace("'", "''")
    _org_filename = data['org_file_name'].replace("'", "''")
    _secure_filename = data['secured_file_name'].replace("'", "''")
    _mobile = data['mobile'].replace("'", "''")
    _ip = data['ip'].replace("'", "''")

    _file_info = json.dumps(data['data'])
    _AESCipher = AESCipher(_mobile)
    _file_info = _AESCipher.encrypt(_file_info).decode('ascii')
    _file_info = _file_info.replace("'", "''")


    _query = f"""insert into tg_file_box(c_uid, c_orginal_file_name, c_secured_file_name, c_file_info, c_uploaded_mobile, c_uploaded_ip)
        values('{_uid}', '{_org_filename}', '{_secure_filename}', '{_file_info}', '{_mobile}', '{_ip}')"""

    _r = db.execute(conn.tg, _query)
    return _r['status']

def getIp():
    return request.remote_addr

def getFileInfo(uid):
    _query = f"""select c_orginal_file_name as orginal_file_name, c_secured_file_name as secured_file_name, c_file_info as file_info, c_uploaded_mobile as user_mobile, n_deleted as deleted from tg_file_box where c_uid = '{uid}'"""
    _r = db.select(conn.tg, _query)
    
    _file_info = _r['data'][0]['file_info']
    isJson = False

    try:
        _file_info = json.loads(_file_info)
        isJson = True
    except:
        isJson = False

    if not isJson:
        print('h')
        _file_info.encode('ascii')

    _mobile = _r['data'][0]['user_mobile']

    _AESCipher = AESCipher(_mobile)
    _file_info = json.loads(_AESCipher.decrypt(_file_info))

    _data = {
        'orginal_file_name' : _r['data'][0]['orginal_file_name'],
        'secured_file_name' : _r['data'][0]['secured_file_name'],
        'deleted' : _r['data'][0]['deleted'],
        'file_info' : _file_info
    }

    return _data

def logDownload(uid):
    _query = f"update tg_file_box set n_downloaded = 1, t_ltime = now() where c_uid = '{uid}'"
    _r = db.execute(conn.tg, _query)

    _ip = getIp()
    _query = f"insert into tg_file_download_log(c_uid, c_ip) values ('{uid}', '{_ip}')"
    _r = db.execute(conn.tg, _query)
    return 

@app.route('/')
def home():
    return render_template('login.html')
    # return render_template('index.html', results = x)
    
@app.route('/generateotp/', methods=['GET', 'POST'])
def generateotp():
    if request.method == 'POST':
        _mobile = request.form['username']
        if _mobile == None or len(_mobile) != 10:
            return redirect(url_for('login', error = "Invalid Mobile Number"))

        return render_template('login.html', mobile = _mobile)

    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        _action = request.form['action']
        _mobile = request.form['username']

        if _action == "generate-otp":
            if _mobile == None or len(_mobile) != 10:
                return redirect(url_for('login', error = "Invalid Mobile Number"))

        elif _action == "submit-otp":
            _password = request.form['password']
            if _password != "0011":
                return render_template('login.html', mobile = _mobile, error = "Invalid OTP")

            session['logged_in'] = True
            session['mobile'] = _mobile
            return redirect(url_for('upload_file'))

        return render_template('login.html', mobile = _mobile)

            
    if request.method == 'GET':
        error = request.args.get('error', None)

    return render_template('login.html', error=error)


@app.route('/logout/')
def logout():
    session['logged_in'] = False
    session['mobile'] = None
    return redirect(url_for('login'))

@app.route('/upload-file/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        uid = request.args.get('file_id', None)
        if uid != None:
            _data = getFileInfo(uid)
            _file_download_link = request.host_url + "download/" + uid
            return render_template('upload.html', uid = uid, file_name = _data['orginal_file_name'], download_link = _file_download_link)

        return render_template('upload.html')


    if request.method == 'POST':
        # try:
        if 1 == 1:
            _mobile = session['mobile']
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                print('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                print('No selected file')
                return redirect(request.url)

            # if file and allowed_file(file.filename):
            if file:
                print('uploading')
                filename = secure_filename(file.filename)
                _org_filename = file.filename
                _secure_filename = filename
                _uid = str(uuid.uuid4())

                _tg = tgClient()
                loop = asyncio.new_event_loop()
                
                _r = None
                filePath = None
                if not uploadFromBlob:
                    _dir = os.path.join(app.config['UPLOAD_FOLDER'], _uid)
                    os.mkdir(_dir)
                    filePath = os.path.join(_dir, filename)
                    
                    file.save(filePath)
                    r = loop.run_until_complete(_tg.uploadFile(loop, filePath, 'Uploaded From vis-tg-file-share: ' + _uid))
                    os.remove(filePath)
                    os.rmdir(_dir)


                if uploadFromBlob:
                    _file_blob = file.read()

                    r = loop.run_until_complete(_tg.uploadBlob(loop, _file_blob, 'Uploaded From vis-tg-file-share: ' + _uid))
                
                _ip = getIp()
                file_info = {
                    'file_uid' : _uid,
                    'physical_path' : filePath,
                    'org_file_name' : _org_filename,
                    'secured_file_name' : _secure_filename,
                    'mobile' : _mobile,
                    'ip' : _ip,
                    'data' : r
                }

                writeFileBox(file_info)
                _msg = f'<h2>File uploaded</h2><br/>File Id: {_uid}<br/>File Name: {_org_filename}'
                # return redirect(url_for('uploaded_file',
                #                     filename=filename))
                return redirect(url_for('upload_file',
                                        file_id=_uid))

            # flash('Extention not allowed')
            print('Extention not allowed')
            return 'Extention not allowed'

        # except:
        #     print('Exception')

    return ''

def callback(current, total):
    print('Downloaded', current, 'out of', total,
          'bytes: {:.2%}'.format(current / total))


@app.route('/download/<uid>', methods=['GET', 'POST'])
def download(uid):
    _data = getFileInfo(uid)
    _fileType = "Document"
    _fileSize = 0
    _file_info = _data['file_info']
    
    # _file_info = json.loads(_file_info)

    if request.method == 'GET':
        if 'mime_type' in _file_info:
            _fileType = _file_info['mime_type']

        if 'size' in _file_info:
            _fileSize = _file_info['size']

        if _fileSize < 1024:
            _fileSize = str(_fileSize) + "b"
        elif _fileSize < (1024 * 1024):
            _fileSize = str(round(_fileSize / 1024, 2)) + "KB"
        elif _fileSize < (1024 * 1024 * 1024):
            _fileSize = str(round(_fileSize / 1024 / 1024, 2)) + "MB"
        elif _fileSize < (1024 * 1024 * 1024 * 1024):
            _fileSize = str(round(_fileSize / 1024 / 1024 / 1024, 2)) + "GB"

        return render_template('download.html', uid = uid, file_name = _data['orginal_file_name'], file_type = _fileType, file_size = _fileSize, is_deleted = _data['deleted'])

    _account = _file_info['account']
    _file_hash = _file_info['access_hash']
    _file_id = _file_info['file_id']
    _file_name = _file_info['file_name']
    _secure_filename = _data['secured_file_name']
    _message_id = _file_info['message_id']
    
    # _tg = tgClient()
    # loop = asyncio.new_event_loop()
    # _dir = os.path.join(app.config['UPLOAD_FOLDER'], uid)
    # if not os.path.exists(_dir):
    #     os.mkdir(_dir)
        
    # filePath = os.path.join(_dir, _secure_filename)
    # if not os.path.exists(filePath):
    #     r = loop.run_until_complete(_tg.downloadFile(loop, _account, _message_id, filePath))

    # r = loop.run_until_complete(_tg.downloadFile(loop, _account, _message_id, filePath))

    return _data


@app.route('/download-file/<uid>', methods=['GET'])
def download_file(uid):
    _data = getFileInfo(uid)
    if _data['deleted']:
        return None
        
    _fileType = "Document"
    _fileSize = 0
    _file_info = _data['file_info']
    # _file_info = json.loads(_file_info)

    _account = _file_info['account']
    _file_hash = _file_info['access_hash']
    _file_id = _file_info['file_id']
    _file_name = _file_info['file_name']
    _secure_filename = _data['secured_file_name']
    _message_id = _file_info['message_id']
    
    _tg = tgClient()
    loop = asyncio.new_event_loop()
    _dir = os.path.join(app.config['UPLOAD_FOLDER'], uid)
    if not os.path.exists(_dir):
        os.mkdir(_dir)
        
    filePath = ""
    filePath = os.path.join(_dir, _secure_filename)
    _mime_type = 'application/document'
    if 'mime_type' in _file_info:
        _mime_type = _file_info['mime_type']
    else:
        if _file_info['media']['type'] == "MessageMediaPhoto":
            _f = _secure_filename.split('.')
            _f = _f[len(_f) - 1]

            _mime_type = 'image/' + _f
            if _f == "jpg":
                _mime_type = 'image/jpeg'


    # if not os.path.exists(filePath):
    #     r = loop.run_until_complete(_tg.downloadFile(loop, _account, _message_id, filePath))

    r = loop.run_until_complete(_tg.downloadFile(loop, _account, _message_id, filePath))

    _enc_data = base64.b64encode(r)
    # print(_enc_data)
    logDownload(uid)
    return _enc_data

    # return send_file(
    #     io.BytesIO(r),
    #     mimetype=_mime_type,
    #     as_attachment=True,
    #     attachment_filename=_secure_filename)
    # return r 

    # return send_from_directory(_dir,
    #                            _secure_filename)
    # return request.host_url + filePath

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename, as_attachment=True)

@app.route('/uid/')
def getUid():
    _uid = uuid.uuid4()
    print(_uid)
    return "vv"

if __name__ == '__main__':
    # app.run(debug = True) 
    app.run() 
    # app.run('127.0.0.1' , 5000 , debug=True)
    # app.run('0.0.0.0' , 5001 , threaded=True)
    # app.run('0.0.0.0' , 80 , threaded=True)


    # tgApp = tgClient()
    # r = tgApp.uploadFile('tempFiles/gst_mst.txt')
    # print(r)
